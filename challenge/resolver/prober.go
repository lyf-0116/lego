package resolver

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/internal/errutils"
	"github.com/go-acme/lego/v5/log"
)

// Interface for all challenge solvers to implement.
type solver interface {
	Solve(ctx context.Context, authorization acme.Authorization) error
}

// Interface for challenges like dns, where we can set a record in advance for ALL challenges.
// This saves quite a bit of time vs creating the records and solving them serially.
type preSolver interface {
	PreSolve(ctx context.Context, authorization acme.Authorization) error
}

// Interface for challenges like dns, where we can solve all the challenges before to delete them.
type cleanup interface {
	CleanUp(ctx context.Context, authorization acme.Authorization) error
}

type sequential interface {
	Sequential() (bool, time.Duration)
}

// an authz with the solver and challenge we have chosen.
type selectedAuthSolver struct {
	authz     acme.Authorization
	solver    solver
	challenge acme.Challenge
	identity  challengeIdentity
	hasID     bool
	presented bool
	claim     *recordState
	failed    bool
}

type Prober struct {
	solverManager *SolverManager
}

func NewProber(solverManager *SolverManager) *Prober {
	return &Prober{
		solverManager: solverManager,
	}
}

// Solve Looks through the challenge combinations to find a solvable match.
// Then solves the challenges in series and returns.
func (p *Prober) Solve(ctx context.Context, authorizations []acme.Authorization) error {
	failures := errutils.NewDomainsError("resolver")

	var (
		authSolvers           []*selectedAuthSolver
		authSolversSequential []*selectedAuthSolver
	)

	// Loop through the resources, basically through the domains.
	// First pass just selects a solver for each authz.

	for _, authz := range authorizations {
		domain := challenge.GetTargetedDomain(authz)
		if authz.Status == acme.StatusValid {
			// Boulder might recycle recent validated authz (see issue #267)
			log.Info("Authorization is already valid; skipping the challenge.", log.DomainAttr(domain))
			continue
		}

		if solvr, chlg := p.solverManager.chooseSolverAndChallenge(authz); solvr != nil {
			authSolver := &selectedAuthSolver{
				authz:     authz,
				solver:    solvr,
				challenge: chlg,
				hasID:     chlg.Type != "",
			}

			if authSolver.hasID {
				authSolver.identity = newChallengeIdentity(authz, chlg)
			}

			switch s := solvr.(type) {
			case sequential:
				if ok, _ := s.Sequential(); ok {
					authSolversSequential = append(authSolversSequential, authSolver)
				} else {
					authSolvers = append(authSolvers, authSolver)
				}
			default:
				authSolvers = append(authSolvers, authSolver)
			}
		} else {
			failures.Add(domain, errors.New("prober: could not determine solvers"))
		}
	}

	parallelSolve(ctx, authSolvers, failures)

	sequentialSolve(ctx, authSolversSequential, failures)

	return failures.Join()
}

func sequentialSolve(ctx context.Context, authSolvers []*selectedAuthSolver, failures *errutils.DomainsError) {
	registry := newRecordRegistry()

	// Count all users of each record up front so a record created by the first
	// occurrence stays alive until its last occurrence has been solved.
	remaining := make(map[recordKey]int)
	for _, authSolver := range authSolvers {
		if _, ok := authSolver.solver.(preSolver); ok && authSolver.hasID {
			remaining[authSolver.identity.recordKey]++
		}
	}

	for i, authSolver := range authSolvers {
		// Submit the challenge
		domain := challenge.GetTargetedDomain(authSolver.authz)

		if solvr, ok := authSolver.solver.(preSolver); ok {
			if authSolver.hasID {
				key := authSolver.identity.recordKey

				state, created := registry.claim(key, authSolver.authz, authSolver.solver)
				authSolver.claim = state

				if created {
					err := solvr.PreSolve(ctx, authSolver.authz)
					if err != nil {
						failures.Add(domain, err)
						authSolver.failed = true

						registry.cancel(key, state)
						authSolver.claim = nil
					} else {
						registry.presented(state)
						authSolver.presented = true
					}
				} else {
					log.Debug("Duplicate challenge identity; skipping pre-solve.",
						log.DomainAttr(domain),
						slog.String("type", authSolver.challenge.Type),
						slog.String("token", authSolver.identity.Token),
					)
				}
			} else {
				err := solvr.PreSolve(ctx, authSolver.authz)
				if err != nil {
					failures.Add(domain, err)
					authSolver.failed = true
				} else {
					authSolver.presented = true
				}
			}
		}

		if authSolver.failed {
			releaseSequential(ctx, registry, authSolver, remaining)

			continue
		}

		// Solve the challenge
		err := authSolver.solver.Solve(ctx, authSolver.authz)
		if err != nil {
			failures.Add(domain, err)
			authSolver.failed = true
		}

		releaseSequential(ctx, registry, authSolver, remaining)

		if authSolver.failed {
			continue
		}

		if len(authSolvers)-1 > i {
			solvr := authSolver.solver.(sequential)
			_, interval := solvr.Sequential()
			log.Info("sequence: wait.", slog.Duration("interval", interval), log.DomainAttr(domain))
			time.Sleep(interval)
		}
	}
}

func releaseSequential(ctx context.Context, registry *recordRegistry, authSolver *selectedAuthSolver, remaining map[recordKey]int) {
	_, isPreSolver := authSolver.solver.(preSolver)

	if isPreSolver && authSolver.hasID {
		key := authSolver.identity.recordKey
		remaining[key]--

		if authSolver.claim == nil {
			return
		}

		state, clean := registry.release(key, authSolver.claim, remaining[key] == 0)
		authSolver.claim = nil

		if clean {
			cleanUp(ctx, state.solver, state.authz)
		}

		return
	}

	if isPreSolver && !authSolver.presented {
		return
	}

	cleanUp(ctx, authSolver.solver, authSolver.authz)
}

func parallelSolve(ctx context.Context, authSolvers []*selectedAuthSolver, failures *errutils.DomainsError) {
	registry := newRecordRegistry()

	var anonymous []*selectedAuthSolver

	// For all valid preSolvers, first submit the challenges, so they have max time to propagate
	for _, authSolver := range authSolvers {
		solvr, ok := authSolver.solver.(preSolver)
		if !ok {
			continue
		}

		domain := challenge.GetTargetedDomain(authSolver.authz)

		if authSolver.hasID {
			key := authSolver.identity.recordKey

			state, created := registry.claim(key, authSolver.authz, authSolver.solver)
			authSolver.claim = state

			if !created {
				log.Debug("Duplicate token; skipping pre-solve.",
					log.DomainAttr(domain),
					slog.String("type", authSolver.challenge.Type),
					slog.String("token", authSolver.identity.Token),
				)

				continue
			}

			err := solvr.PreSolve(ctx, authSolver.authz)
			if err != nil {
				failures.Add(domain, err)
				authSolver.failed = true

				registry.cancel(key, state)
				authSolver.claim = nil
			} else {
				registry.presented(state)
				authSolver.presented = true
			}
		} else {
			err := solvr.PreSolve(ctx, authSolver.authz)
			if err != nil {
				failures.Add(domain, err)
				authSolver.failed = true
			} else {
				anonymous = append(anonymous, authSolver)
				authSolver.presented = true
			}
		}
	}

	// Finally, solve all challenges for real.
	for _, authSolver := range authSolvers {
		if authSolver.failed {
			continue
		}

		err := authSolver.solver.Solve(ctx, authSolver.authz)
		if err != nil {
			failures.Add(challenge.GetTargetedDomain(authSolver.authz), err)
		}
	}

	for _, state := range registry.cleanupAll() {
		cleanUp(ctx, state.solver, state.authz)
	}

	for _, authSolver := range anonymous {
		cleanUp(ctx, authSolver.solver, authSolver.authz)
	}

	for _, authSolver := range authSolvers {
		if _, ok := authSolver.solver.(preSolver); ok {
			continue
		}

		cleanUp(ctx, authSolver.solver, authSolver.authz)
	}
}

func cleanUp(ctx context.Context, solvr solver, authz acme.Authorization) {
	s, ok := solvr.(cleanup)
	if !ok {
		return
	}

	err := s.CleanUp(ctx, authz)
	if err != nil {
		log.Warn("Cleaning up failed.",
			log.DomainAttr(challenge.GetTargetedDomain(authz)),
			log.ErrorAttr(err))
	}
}
