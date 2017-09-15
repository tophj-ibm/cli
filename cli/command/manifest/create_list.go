package manifest

import (
	"fmt"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/manifest/store"
	"github.com/docker/docker/registry"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
)

type annotateOpts struct {
	amend bool
}

func newCreateListCommand(dockerCli command.Cli) *cobra.Command {
	opts := annotateOpts{}

	cmd := &cobra.Command{
		Use:   "create MANFEST_LIST MANIFEST [MANIFEST...]",
		Short: "Create a local manifest list for annotating and pushing to a registry",
		Args:  cli.RequiresMinArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return createManifestList(dockerCli, args, opts)
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&opts.amend, "amend", "a", false, "Amend an existing manifest list")
	return cmd
}

func createManifestList(dockerCli command.Cli, args []string, opts annotateOpts) error {
	newRef := args[0]
	targetRef, err := normalizeReference(newRef)
	if err != nil {
		return errors.Wrapf(err, "error parsing name for manifest list (%s): %v", newRef)
	}

	_, err = registry.ParseRepositoryInfo(targetRef)
	if err != nil {
		return errors.Wrapf(err, "error parsing repository name for manifest list (%s): %v", newRef)
	}

	manifestStore := dockerCli.ManifestStore()
	_, err = manifestStore.GetList(targetRef)
	switch {
	case store.IsNotFound(err):
		// New manifest list
	case err != nil:
		return err
	case !opts.amend:
		return errors.Errorf("refusing to amend an existing manifest list with no --amend flag")
	}

	ctx := context.Background()
	// Now create the local manifest list transaction by looking up the manifest schemas
	// for the constituent images:
	manifests := args[1:]
	for _, manifestRef := range manifests {
		namedRef, err := normalizeReference(manifestRef)
		if err != nil {
			// TODO: wrap error?
			return err
		}

		manifest, err := getManifest(ctx, dockerCli, targetRef, namedRef)
		if err != nil {
			return err
		}
		if err := manifestStore.Save(targetRef, namedRef, manifest); err != nil {
			return err
		}
	}
	fmt.Fprintf(dockerCli.Out(), "Created manifest list %s\n", targetRef.String())
	return nil
}
