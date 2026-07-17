# Governance

Agent Tree RL currently uses a single-maintainer model.

## Maintainer

- [Mohamad Kamar](https://github.com/Mohamad-Kamar)

The maintainer owns release decisions, security response, roadmap priority, and
the final interpretation of project scope. This authority does not override the
published license or contributor rights.

## Decision process

Small, reversible changes use normal pull-request review. Changes to public
contracts, safety policy, benchmark semantics, trust boundaries, storage, or
governance start with a GitHub discussion and a written decision in the pull
request or architecture documentation.

Decisions favor:

1. hard safety and correctness constraints before learned reward;
2. explicit evidence and reproducible proof;
3. backwards-compatible public contracts;
4. simple operator paths;
5. local control and no default phone-home telemetry.

## Releases

Only the maintainer may publish official tags and release artifacts. A release
must pass the repository release preflight, be built by GitHub Actions, and
include release notes. Security fixes may ship outside the normal cadence.

## Becoming a maintainer

Regular contributors may be invited after sustained, high-quality work across
code, review, documentation, and community support. Maintainers must disclose
relevant conflicts and use least-privilege repository access.

If the sole maintainer can no longer continue, ownership should transfer to an
active trusted contributor or the repository should be archived with an explicit
status notice.
