package resolver

import (
	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/challenge"
)

// recordKey identifies the provider resource created for a challenge.
//
// The fields are deliberately kept separate: concatenating them can produce
// the same string for different identities (for example "example.com"+"ab"
// and "example.coma"+"b").
//
// Wildcard is not part of a record key because DNS-01 uses the same record
// name for an identifier and its wildcard form. The provider API also only
// receives the identifier value and the token.
type recordKey struct {
	Type       challenge.Type
	Identifier acme.Identifier
	Token      string
}

// challengeIdentity is the identity of an authorization's selected challenge.
// It is used for failure attribution, while recordKey is used for the provider
// resource shared by authorizations with the same identity.
type challengeIdentity struct {
	recordKey

	Wildcard bool
}

func newChallengeIdentity(authz acme.Authorization, chlg acme.Challenge) challengeIdentity {
	return challengeIdentity{
		recordKey: recordKey{
			Type:       challenge.Type(chlg.Type),
			Identifier: authz.Identifier,
			Token:      chlg.Token,
		},
		Wildcard: authz.Wildcard,
	}
}

// recordState is the reference-counted state of a provider resource.
type recordState struct {
	authz     acme.Authorization
	solver    solver
	refs      int
	presented bool
}

type recordRegistry struct {
	records map[recordKey]*recordState
}

func newRecordRegistry() *recordRegistry {
	return &recordRegistry{records: make(map[recordKey]*recordState)}
}

// claim registers a user of the record.
// It returns created=true when the caller is responsible for creating it.
func (r *recordRegistry) claim(key recordKey, authz acme.Authorization, solvr solver) (*recordState, bool) {
	if state, ok := r.records[key]; ok {
		state.refs++
		return state, false
	}

	state := &recordState{authz: authz, solver: solvr, refs: 1}
	r.records[key] = state

	return state, true
}

// presented marks the record as successfully created.
func (r *recordRegistry) presented(state *recordState) {
	state.presented = true
}

// cancel removes a claim that never created a record.
// A failed presentation must not leave a placeholder behind: a later
// authorization with the same identity has to be able to try again.
func (r *recordRegistry) cancel(key recordKey, state *recordState) {
	state.refs--

	if r.records[key] == state {
		delete(r.records, key)
	}
}

// release removes a user of the record.
// When last is true, the record is removed from the registry and the caller is
// told which resource must be cleaned up.
func (r *recordRegistry) release(key recordKey, state *recordState, last bool) (*recordState, bool) {
	state.refs--

	if !last {
		return nil, false
	}

	if r.records[key] == state {
		delete(r.records, key)
	}

	if !state.presented {
		return nil, false
	}

	return state, true
}

// cleanupAll cleans every record that is still registered.
// It is used by the parallel path, where all users are done solving.
func (r *recordRegistry) cleanupAll() []*recordState {
	states := make([]*recordState, 0, len(r.records))

	for key, state := range r.records {
		delete(r.records, key)

		if state.presented {
			states = append(states, state)
		}
	}

	return states
}
