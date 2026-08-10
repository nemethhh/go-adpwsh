package adpwsh

import (
	"context"
	"fmt"

	"github.com/nemethhh/go-adpwsh/internal/addn"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// ouProject is the -Properties projection for an OU read: only what is in
// scope, never "*" (correctness rule 10).
var ouProject = []string{"Description", "ProtectedFromAccidentalDeletion"}

// OUClient is the organizational-unit sub-client.
type OUClient struct{ c *core }

type ouJSON struct {
	GUID        string `json:"objectGUID"`
	DN          string `json:"distinguishedName"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Protected   bool   `json:"protected"`
}

func (j ouJSON) model() (*OU, error) {
	container, err := containerOf(j.DN)
	if err != nil {
		return nil, err
	}
	return &OU{
		GUID: j.GUID, DN: j.DN, Name: j.Name, Container: container,
		Description: j.Description, Protected: j.Protected,
	}, nil
}

// Create makes an organizational unit and returns the result of the same read
// Get performs, so an inconsistent result after apply is impossible by
// construction.
//
// It may return a non-nil OU together with a non-nil error: that is the
// replication-timeout contract. The object exists and the wait did not
// complete, so the caller must persist the model and surface the error.
// Ignoring the model orphans the object.
func (o *OUClient) Create(ctx context.Context, spec OUSpec) (*OU, error) {
	const op = "OU.Create"
	if err := validateName(op, spec.Name); err != nil {
		return nil, err
	}
	if err := validateContainer(op, spec.Container); err != nil {
		return nil, err
	}

	create := map[string]any{"Name": spec.Name, "Path": spec.Container}
	if spec.Description != nil && *spec.Description != "" {
		create["Description"] = *spec.Description
	}
	if spec.Protected != nil {
		create["ProtectedFromAccidentalDeletion"] = *spec.Protected
	}

	var out ouJSON
	err := o.c.exec(ctx, adscript.OpOUCreate, map[string]any{
		"create":  create,
		"project": ouProject,
	}, &out)
	if err != nil {
		return nil, o.c.annotateAlreadyExists(ctx, err, deletedOUFilter(spec.Name, spec.Container))
	}
	model, err := out.model()
	if err != nil {
		return nil, &Error{Kind: KindTransport, Op: op, Err: err}
	}
	return model, o.c.replicate(ctx, model.GUID)
}

// Get reads one organizational unit.
func (o *OUClient) Get(ctx context.Context, id Identity) (*OU, error) {
	var out ouJSON
	if err := o.c.exec(ctx, adscript.OpOURead, map[string]any{
		"identity": id.identityArg(),
		"project":  ouProject,
	}, &out); err != nil {
		return nil, withIdentity(err, "OU.Get", id)
	}
	model, err := out.model()
	if err != nil {
		return nil, &Error{Kind: KindTransport, Op: "OU.Get", Err: err}
	}
	return model, nil
}

// Update folds the attribute write, the rename and the move into one round
// trip, in the order that keeps the DN valid. It never deletes and recreates,
// because that destroys the object's SID and with it every ACL referencing it.
//
// Like Create, it may return a non-nil OU with a non-nil error on a
// replication timeout.
func (o *OUClient) Update(ctx context.Context, id Identity, spec OUSpec) (*OU, error) {
	const op = "OU.Update"
	if err := validateName(op, spec.Name); err != nil {
		return nil, err
	}
	if err := validateContainer(op, spec.Container); err != nil {
		return nil, err
	}

	unlock := o.c.locks.lock(id.identityArg())
	defer unlock()

	current, err := o.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	payload := map[string]any{"identity": id.identityArg(), "project": ouProject}

	var ops adscript.AttrOps
	set := map[string]any{"Identity": id.identityArg()}
	applyStringField(&ops, set, "Description", "description", spec.Description)
	if spec.Protected != nil && *spec.Protected != current.Protected {
		set["ProtectedFromAccidentalDeletion"] = *spec.Protected
	}
	if err := conflictToError(op, ops.Apply(set)); err != nil {
		return nil, err
	}
	if len(set) > 1 {
		payload["set"] = set
	}

	if spec.Name != current.Name {
		payload["rename"] = map[string]any{"Identity": id.identityArg(), "NewName": spec.Name}
	}
	sameContainer, err := addn.EqualFold(spec.Container, current.Container)
	if err != nil {
		return nil, &Error{Kind: KindConstraint, Op: op, Err: err}
	}
	if !sameContainer {
		payload["move"] = map[string]any{"Identity": id.identityArg(), "TargetPath": spec.Container}
	}

	if payload["set"] == nil && payload["rename"] == nil && payload["move"] == nil {
		return current, nil
	}

	var out ouJSON
	if err := o.c.exec(ctx, adscript.OpOUUpdate, payload, &out); err != nil {
		return nil, withIdentity(err, op, id)
	}
	model, err := out.model()
	if err != nil {
		return nil, &Error{Kind: KindTransport, Op: op, Err: err}
	}
	return model, o.c.replicate(ctx, model.GUID)
}

// Delete removes an organizational unit and returns nil only after a re-read
// confirms it is gone. A non-empty OU is never deleted recursively: the error
// names the child count. Remove-ADOrganizationalUnit -Recursive exists and is
// deliberately not reachable from this API.
func (o *OUClient) Delete(ctx context.Context, id Identity, opts DeleteOptions) error {
	const op = "OU.Delete"

	unlock := o.c.locks.lock(id.identityArg())
	defer unlock()

	current, err := o.Get(ctx, id)
	if err != nil {
		return err
	}

	var out struct {
		Deleted    bool          `json:"deleted"`
		ChildCount int           `json:"childCount"`
		Verify     presenceCheck `json:"verify"`
	}
	if err := o.c.exec(ctx, adscript.OpOUDelete, map[string]any{
		"identity":  current.GUID,
		"dn":        current.DN,
		"unprotect": opts.Unprotect,
	}, &out); err != nil {
		return withIdentity(err, op, id)
	}
	if !out.Deleted {
		return &Error{
			Kind: KindConstraint, Op: op, Identity: id.String(), Target: current.DN,
			Err: fmt.Errorf("organizational unit has %d child object(s); delete or move them first "+
				"(recursive deletion is deliberately not offered)", out.ChildCount),
		}
	}
	return out.Verify.confirmAbsent(op, id, current.DN)
}

// deletedOUFilter looks for a tombstoned OU under the same parent. Deleted
// objects keep a mangled name, so the probe matches on lastKnownParent and the
// name prefix rather than on an exact name.
func deletedOUFilter(name, container string) string {
	return "(&(isDeleted=TRUE)(objectClass=organizationalUnit)(lastKnownParent=" +
		addn.EscapeFilter(container) + ")(name=" + addn.EscapeFilter(name) + "*))"
}
