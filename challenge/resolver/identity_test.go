package resolver

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProber_Solve_identity(t *testing.T) {
	testCases := []struct {
		desc          string
		sequential    bool
		authz         []acme.Authorization
		preSolveError map[string]error
		solveError    map[string]error
		expectedError string
		expected      string
	}{
		{
			desc: "structured key does not collide",
			authz: []acme.Authorization{
				createTokenAuthorization("a.example", false, "bc"),
				createTokenAuthorization("a.exampleb", false, "c"),
			},
			expected: "PreSolve: 2, Solve: 2, CleanUp: 2",
		},
		{
			desc: "parallel duplicate identity is presented once",
			authz: []acme.Authorization{
				createTokenAuthorization("a.example", false, "token"),
				createTokenAuthorization("a.example", true, "token"),
			},
			expected: "PreSolve: 1, Solve: 2, CleanUp: 1",
		},
		{
			desc: "parallel failed presentation does not reserve the record",
			authz: []acme.Authorization{
				createTokenAuthorization("a.example", false, "token"),
				createTokenAuthorization("a.example", true, "token"),
			},
			preSolveError: map[string]error{
				"a.example\x00token": errors.New("pre-solve failed"),
			},
			expectedError: "a.example: pre-solve failed",
			expected:      "PreSolve: 2, Solve: 1, CleanUp: 1",
		},
		{
			desc:       "sequential duplicate identity is solved and cleaned once",
			sequential: true,
			authz: []acme.Authorization{
				createTokenAuthorization("a.example", false, "token"),
				createTokenAuthorization("a.example", true, "token"),
			},
			expected: "PreSolve: 1, Solve: 2, CleanUp: 1",
		},
		{
			desc:       "sequential record lives until its last user",
			sequential: true,
			authz: []acme.Authorization{
				createTokenAuthorization("a.example", false, "token"),
				createTokenAuthorization("b.example", false, "token"),
				createTokenAuthorization("a.example", true, "token"),
			},
			expected: "PreSolve: 2, Solve: 3, CleanUp: 2",
		},
		{
			desc:       "sequential failed presentation can be retried",
			sequential: true,
			authz: []acme.Authorization{
				createTokenAuthorization("a.example", false, "token"),
				createTokenAuthorization("a.example", true, "token"),
			},
			preSolveError: map[string]error{
				"a.example\x00token": errors.New("pre-solve failed"),
			},
			expectedError: "a.example: pre-solve failed",
			expected:      "PreSolve: 2, Solve: 1, CleanUp: 1",
		},
		{
			desc:       "sequential solve failure does not skip the duplicate",
			sequential: true,
			authz: []acme.Authorization{
				createTokenAuthorization("a.example", false, "token"),
				createTokenAuthorization("a.example", true, "token"),
			},
			solveError: map[string]error{
				"a.example\x00token": errors.New("solve failed"),
			},
			expectedError: "a.example: solve failed",
			expected:      "PreSolve: 1, Solve: 2, CleanUp: 1",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			solvr := &identitySolverMock{
				sequential:     test.sequential,
				preSolveErrors: test.preSolveError,
				solveErrors:    test.solveError,
			}

			prober := &Prober{
				solverManager: &SolverManager{
					solvers: map[challenge.Type]solver{challenge.DNS01: solvr},
				},
			}

			err := prober.Solve(t.Context(), test.authz)
			if test.expectedError == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.expectedError)
			}

			assert.Equal(t, test.expected, solvr.String())
		})
	}
}

type identitySolverMock struct {
	sequential     bool
	preSolveErrors map[string]error
	solveErrors    map[string]error

	preSolveCalls int
	solveCalls    int
	cleanUpCalls  int
}

func (s *identitySolverMock) PreSolve(_ context.Context, authz acme.Authorization) error {
	s.preSolveCalls++

	return s.preSolveErrors[s.identity(authz)]
}

func (s *identitySolverMock) Solve(_ context.Context, authz acme.Authorization) error {
	s.solveCalls++

	return s.solveErrors[s.identity(authz)]
}

func (s *identitySolverMock) CleanUp(_ context.Context, _ acme.Authorization) error {
	s.cleanUpCalls++

	return nil
}

func (s *identitySolverMock) Sequential() (bool, time.Duration) {
	return s.sequential, 0
}

func (s *identitySolverMock) String() string {
	return fmt.Sprintf("PreSolve: %d, Solve: %d, CleanUp: %d", s.preSolveCalls, s.solveCalls, s.cleanUpCalls)
}

func (s *identitySolverMock) identity(authz acme.Authorization) string {
	chlg, _ := challenge.FindChallenge(challenge.DNS01, authz)

	return challenge.GetTargetedDomain(authz) + "\x00" + chlg.Token
}

func createTokenAuthorization(domain string, wildcard bool, token string) acme.Authorization {
	return acme.Authorization{
		Wildcard: wildcard,
		Status:   acme.StatusProcessing,
		Expires:  time.Now(),
		Identifier: acme.Identifier{
			Type:  "dns",
			Value: domain,
		},
		Challenges: []acme.Challenge{
			{
				Type:      challenge.DNS01.String(),
				Token:     token,
				Validated: time.Now(),
			},
		},
	}
}
