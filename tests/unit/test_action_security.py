from pathlib import Path

import yaml


def test_badge_publishing_is_default_branch_only_in_temporary_clone():
    action = yaml.safe_load(Path("integrations/github-action/action.yml").read_text())
    step = next(s for s in action["runs"]["steps"] if s.get("name") == "Publish the badge")
    assert (
        "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)"
        in step["if"]
    )
    script = step["run"]
    assert "mktemp -d" in script and "git clone" in script
    assert script.index('cd "$badge_dir/repo"') < script.index("git rm")
