#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Remove what a build or a measurement produced, and nothing else.
#
# A list of build products kept in two places falls behind what the repository
# accumulates, so this script is the one definition, and `make clean` calls it.
#
# Every path is derived from the tree it is run in, and a path that resolves outside that
# tree is refused rather than removed. The datasets under a sweep output directory are
# deliberately not in scope: they are hours of VM time and they live outside the checkout.
#
# It reports what it removed, what was already absent, and how much it reclaimed, because
# a cleaner that prints nothing is indistinguishable from one that matched nothing.

set -euo pipefail

usage() {
    cat <<'EOF'
usage: hack/clean.sh [--dry-run] [--worktrees] [--keep-target]

  --dry-run      list what would be removed and remove nothing
  --worktrees    clean every worktree of this repository, not only this one
  --keep-target  leave target/ alone; remove only measurement and mutation output

--worktrees reaches trees somebody else may be building in. Run --dry-run first and
read the list; a target/ directory that is larger than you expected is usually a
session at work in it.

Run from anywhere inside the checkout, or inside any of its worktrees.
EOF
}

dry_run=false
worktrees=false
keep_target=false

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) dry_run=true ;;
        --worktrees) worktrees=true ;;
        --keep-target) keep_target=true ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "clean: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if ! root=$(git rev-parse --show-toplevel 2>/dev/null); then
    echo "clean: not inside a git checkout, and every path here is derived from one" >&2
    exit 2
fi

removed=0
absent=0
reclaimed_kb=0

# `du -sk` rather than `-sb`: kilobytes are in POSIX and bytes are a GNU extension, and
# this has to run on the macOS host the Darwin lane is measured on.
size_kb() {
    du -sk "$1" 2>/dev/null | awk '{print $1}' || echo 0
}

# Refuse anything that does not resolve inside the tree we were pointed at. A glob that
# matched nothing, a symlink out of the checkout, an argument that arrived by surprise:
# all of them end here rather than at `rm -rf`.
drop() {
    local path=$1 tree=$2
    case "$path" in
        "$tree"/*) ;;
        *)
            echo "clean: refusing $path -- outside $tree" >&2
            return 1
            ;;
    esac
    if [ ! -e "$path" ]; then
        absent=$((absent + 1))
        return 0
    fi
    local kb
    kb=$(size_kb "$path")
    reclaimed_kb=$((reclaimed_kb + kb))
    removed=$((removed + 1))
    if $dry_run; then
        printf '  would remove  %-40s %6s MiB\n' "${path#"$tree"/}" "$((kb / 1024))"
    else
        printf '  removed       %-40s %6s MiB\n' "${path#"$tree"/}" "$((kb / 1024))"
        rm -rf -- "$path"
    fi
}

clean_tree() {
    local tree=$1
    echo "clean: $tree"

    if ! $keep_target; then
        # `cargo clean` rather than `rm -rf target`, where cargo is available: it knows
        # about the package-verification and per-target directories this script does not
        # have to learn the names of.
        if $dry_run; then
            drop "$tree/target" "$tree" || true
        elif command -v cargo >/dev/null 2>&1; then
            local kb
            kb=$(size_kb "$tree/target")
            if [ -e "$tree/target" ]; then
                (cd "$tree" && cargo clean)
                reclaimed_kb=$((reclaimed_kb + kb))
                removed=$((removed + 1))
                printf '  removed       %-40s %6s MiB\n' "target (cargo clean)" "$((kb / 1024))"
            else
                absent=$((absent + 1))
            fi
        else
            drop "$tree/target" "$tree" || true
        fi
    fi

    # The fuzz crate's own build output (`fuzz/` is outside chard's workspace, so `cargo
    # clean` above does not reach it). Its corpus and crash artifacts stay: they are what
    # the fuzzer found, and `make fuzz-replay` reruns them.
    if ! $keep_target; then
        drop "$tree/fuzz/target" "$tree" || true
    fi

    # The default --workdir, holding probe sources, artifacts and the captured stdout and
    # stderr a measurement keeps as evidence. A build product of a run, not a source.
    drop "$tree/chard-work" "$tree" || true

    # `make clang` writes this and `make clean` already removed it.
    drop "$tree/chard-clang.json" "$tree" || true

    # `make sweep` writes each cell's report, its workdir and its candidate expectation
    # file here. The reports are the evidence behind a sweep's verdict; locally they are a
    # product of the run, as chard-work is.
    drop "$tree/chard-sweep-out" "$tree" || true

    # Mutation output: `mutants.out` plus whatever suffixed copies were kept beside it for
    # comparison. Nothing else in the tree matches this shape, and `nullglob` keeps an
    # unmatched glob from arriving here as a literal.
    local path
    shopt -s nullglob
    for path in "$tree"/mutants.out "$tree"/mutants.out.*; do
        drop "$path" "$tree" || true
    done

    # Captured output from a measurement run at the top level rather than under the
    # workdir, which is where `--workdir .` puts it.
    for path in "$tree"/*.stdout "$tree"/*.stderr; do
        drop "$path" "$tree" || true
    done
    shopt -u nullglob
}

clean_tree "$root"

if $worktrees; then
    # `git worktree list` is the authority on what exists; a hardcoded path under
    # .claude/worktrees would miss one added anywhere else.
    while read -r path _; do
        [ "$path" = "$root" ] && continue
        [ -d "$path" ] || continue
        clean_tree "$path"
    done < <(git worktree list --porcelain | awk '/^worktree /{print $2}')
fi

# The boundary, not only the total: how many paths were considered, so "removed 0" can be
# told apart from "matched nothing because the names have drifted again".
verb=removed
$dry_run && verb="would remove"
echo "clean: $verb $removed path(s), $absent already absent, $((reclaimed_kb / 1024)) MiB reclaimed"
