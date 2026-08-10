package adpwsh_test

import (
	"context"
	"errors"
	"fmt"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/transport/fake"
)

// Example shows the whole contract in one page: a client is a transport plus a
// pinned DC; every write returns the read path's result; a replication timeout
// returns the model and an error together.
func Example() {
	dir := fake.NewDirectory()
	client, err := adpwsh.New(context.Background(), adpwsh.Config{Transport: dir.Transport()})
	if err != nil {
		panic(err)
	}
	defer client.Close()

	ou, err := client.OU.Create(context.Background(), adpwsh.OUSpec{
		Name:      "Staff",
		Container: client.DefaultNamingContext(),
	})
	if err != nil && !errors.Is(err, adpwsh.ErrReplication) {
		panic(err)
	}
	fmt.Println(ou.DN, ou.Protected)
	// Output: OU=Staff,DC=corp,DC=local true
}
