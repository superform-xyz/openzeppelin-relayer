#!/bin/sh

# Regex pattern for semantic commit messages
commit_regex='^(feat|fix|docs|style|refactor|perf|test|chore|build|ci|revert|merge)(\(.+\))?: .{1,50}'

# Get the commit message
commit_message=$(cat "$1")

# Check if the commit message matches the pattern
if ! echo "$commit_message" | grep -Eq "$commit_regex"; then
    echo "Error: Commit message does not follow the semantic commit message format."
    echo "Format: <type>(<scope>): <subject>"
    echo "Example: feat(parser): add ability to parse arrays"
    exit 1
fi