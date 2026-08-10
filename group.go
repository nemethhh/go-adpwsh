package adpwsh

import (
	"context"

	"github.com/nemethhh/go-adpwsh/internal/addn"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

var groupProject = []string{"Description", "ManagedBy", "GroupScope", "GroupCategory", "SamAccountName"}

// GroupClient is the group sub-client.
type GroupClient struct{ c *core }

type groupJSON struct {
	GUID           string `json:"objectGUID"`
	DN             string `json:"distinguishedName"`
	Name           string `json:"name"`
	SamAccountName string `json:"samAccountName"`
	Scope          string `json:"scope"`
	Category       string `json:"category"`
	Description    string `json:"description"`
	ManagedBy      string `json:"managedBy"`
	SID            string `json:"sid"`
}

func (j groupJSON) model() (*Group, error) {
	container, err := containerOf(j.DN)
	if err != nil {
		return nil, err
	}
	return &Group{
		GUID: j.GUID, DN: j.DN, Name: j.Name, SamAccountName: j.SamAccountName,
		Container: container, Scope: GroupScope(j.Scope), Category: GroupCategory(j.Category),
		Description: j.Description, ManagedBy: j.ManagedBy, SID: j.SID,
	}, nil
}

// Create makes a group and returns the result of the same read Get performs.
// It may return a non-nil Group together with a non-nil error on a replication
// timeout; the caller must persist the model and surface the error.
func (g *GroupClient) Create(ctx context.Context, spec GroupSpec) (*Group, error) {
	const op = "Group.Create"
	if err := spec.validate(op, true); err != nil {
		return nil, err
	}
	if spec.Category == "" {
		spec.Category = GroupCategorySecurity
	}
	scope, _ := spec.Scope.cmdletValue()
	category, _ := spec.Category.cmdletValue()

	create := map[string]any{
		"Name":           spec.Name,
		"SamAccountName": spec.SamAccountName,
		"Path":           spec.Container,
		"GroupScope":     scope,
		"GroupCategory":  category,
	}
	if spec.Description != nil && *spec.Description != "" {
		create["Description"] = *spec.Description
	}
	if spec.ManagedBy != nil && *spec.ManagedBy != "" {
		create["ManagedBy"] = *spec.ManagedBy
	}

	var out groupJSON
	if err := g.c.exec(ctx, adscript.OpGroupCreate, map[string]any{
		"create": create, "project": groupProject,
	}, &out); err != nil {
		return nil, g.c.annotateAlreadyExists(ctx, err, deletedPrincipalFilter(spec.SamAccountName))
	}
	model, err := out.model()
	if err != nil {
		return nil, &Error{Kind: KindTransport, Op: op, Err: err}
	}
	return model, g.c.replicate(ctx, model.GUID)
}

// Get reads one group.
func (g *GroupClient) Get(ctx context.Context, id Identity) (*Group, error) {
	var out groupJSON
	if err := g.c.exec(ctx, adscript.OpGroupRead, map[string]any{
		"identity": id.identityArg(), "project": groupProject,
	}, &out); err != nil {
		return nil, withIdentity(err, "Group.Get", id)
	}
	model, err := out.model()
	if err != nil {
		return nil, &Error{Kind: KindTransport, Op: "Group.Get", Err: err}
	}
	return model, nil
}

// Update folds the attribute write, the rename and the move into one round
// trip. Where AD refuses a scope conversion, AD's own error is surfaced.
func (g *GroupClient) Update(ctx context.Context, id Identity, spec GroupSpec) (*Group, error) {
	const op = "Group.Update"
	if err := spec.validate(op, false); err != nil {
		return nil, err
	}

	unlock := g.c.locks.lock(id.identityArg())
	defer unlock()

	current, err := g.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	payload := map[string]any{"identity": id.identityArg(), "project": groupProject}

	var ops adscript.AttrOps
	set := map[string]any{"Identity": id.identityArg()}
	applyStringField(&ops, set, "Description", "description", spec.Description)
	applyStringField(&ops, set, "ManagedBy", "managedBy", spec.ManagedBy)
	if spec.SamAccountName != current.SamAccountName {
		set["SamAccountName"] = spec.SamAccountName
	}
	if spec.Scope != "" && spec.Scope != current.Scope {
		v, _ := spec.Scope.cmdletValue()
		set["GroupScope"] = v
	}
	if spec.Category != "" && spec.Category != current.Category {
		v, _ := spec.Category.cmdletValue()
		set["GroupCategory"] = v
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

	var out groupJSON
	if err := g.c.exec(ctx, adscript.OpGroupUpdate, payload, &out); err != nil {
		return nil, withIdentity(err, op, id)
	}
	model, err := out.model()
	if err != nil {
		return nil, &Error{Kind: KindTransport, Op: op, Err: err}
	}
	return model, g.c.replicate(ctx, model.GUID)
}

// Delete removes a group and returns nil only after a re-read confirms it is
// gone.
func (g *GroupClient) Delete(ctx context.Context, id Identity) error {
	const op = "Group.Delete"

	unlock := g.c.locks.lock(id.identityArg())
	defer unlock()

	current, err := g.Get(ctx, id)
	if err != nil {
		return err
	}
	var out struct {
		Deleted bool          `json:"deleted"`
		Verify  presenceCheck `json:"verify"`
	}
	if err := g.c.exec(ctx, adscript.OpGroupDelete, map[string]any{"identity": current.GUID}, &out); err != nil {
		return withIdentity(err, op, id)
	}
	return out.Verify.confirmAbsent(op, id, current.DN)
}

// deletedPrincipalFilter finds a tombstoned security principal. A deleted
// object keeps its sAMAccountName, which is exactly what blocks re-creation
// with an opaque error.
func deletedPrincipalFilter(sam string) string {
	return "(&(isDeleted=TRUE)(sAMAccountName=" + addn.EscapeFilter(sam) + "))"
}
