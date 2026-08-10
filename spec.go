package adpwsh

import (
	"errors"
	"fmt"

	"github.com/nemethhh/go-adpwsh/internal/addn"
	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// OUSpec is the desired state of an organizational unit. A nil pointer leaves
// the attribute alone; a pointer to "" clears it; a pointer to a value sets it.
type OUSpec struct {
	Name        string // the RDN; required on create, a change means Rename-ADObject
	Container   string // parent DN; required on create, a change means Move-ADObject
	Description *string
	Protected   *bool // ProtectedFromAccidentalDeletion
}

// DeleteOptions is taken only by OU.Delete. Making the unprotect step an
// explicit option keeps the destructive part visible at the call site.
type DeleteOptions struct {
	// Unprotect lifts ProtectedFromAccidentalDeletion before deleting. Without
	// it, deleting an OU created with AD's own default fails.
	Unprotect bool
}

func validateContainer(op, container string) error {
	if container == "" {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("Container is required")}
	}
	if _, err := addn.ParseDN(container); err != nil {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("Container is not a distinguished name: %w", err)}
	}
	return nil
}

func validateName(op, name string) error {
	if name == "" {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("Name is required")}
	}
	return nil
}

// containerOf returns the parent of a DN, which is what the models expose as
// Container. Deriving it means the model and the directory cannot disagree.
func containerOf(dn string) (string, error) {
	return addn.Parent(dn)
}

// applyStringField encodes one tri-state string field: nil leaves it alone,
// "" clears it through -Clear (AD has no empty attribute value), anything else
// sets the cmdlet parameter.
func applyStringField(ops *adscript.AttrOps, splat map[string]any, param, ldapName string, v *string) {
	if v == nil {
		return
	}
	if *v == "" {
		ops.ClearName(ldapName)
		return
	}
	splat[param] = *v
}

// conflictToError converts the payload builder's refusal into the library's
// error type. adscript stays dependency-free, so the translation lives here.
func conflictToError(op string, err error) error {
	if err == nil {
		return nil
	}
	var ce *adscript.ConflictError
	if errors.As(err, &ce) {
		return &Error{Kind: KindConstraint, Op: op, Err: ce}
	}
	return &Error{Kind: KindConstraint, Op: op, Err: err}
}

// presenceCheck is what Test-AdPresence returns. The script never decides
// whether an object is gone: it hands the exception back so the classifier,
// which fails closed, makes the call.
type presenceCheck struct {
	Found     bool   `json:"found"`
	Type      string `json:"type"`
	ErrorCode int    `json:"errorCode"`
	Message   string `json:"message"`
}

// confirmAbsent turns a presence probe into the delete verdict. A destroy that
// silently no-ops is worse than one that fails: Terraform drops the resource
// from state and the object is then unmanaged and invisible.
func (p presenceCheck) confirmAbsent(op string, id Identity, dn string) error {
	if p.Found {
		return &Error{
			Kind: KindConstraint, Op: op, Identity: id.String(), Target: dn,
			Err: fmt.Errorf("the remove cmdlet returned cleanly but the object is still present; " +
				"the deletion was refused"),
		}
	}
	if kind := Classify(p.Type, p.ErrorCode); kind != KindNotFound {
		return &Error{
			Kind: kind, Op: op, Identity: id.String(), Target: dn,
			ExceptionType: p.Type, Code: p.ErrorCode, ServerMessage: p.Message,
			Err: fmt.Errorf("could not verify the deletion"),
		}
	}
	return nil
}

// withIdentity stamps the identity onto an error that came back from a script,
// so a diagnostic can name what was acted on.
func withIdentity(err error, op string, id Identity) error {
	var e *Error
	if asAdpwshError(err, &e) {
		if e.Op == "" {
			e.Op = op
		}
		if e.Identity == "" {
			e.Identity = id.String()
		}
		return e
	}
	return err
}
