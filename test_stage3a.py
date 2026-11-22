import pandas as pd
import pytest

from evaluate_stage3a import check_split_overlap, split_groups


def test_grouped_assignment_is_reproducible_and_keeps_groups_together():
    rows = pd.DataFrame(
        [(group, label) for label in (0, 1) for group in range(label * 20, (label + 1) * 20)
         for _ in range(3)],
        columns=["group_id", "label"],
    )
    assignment = split_groups(rows, seed=42)
    pd.testing.assert_frame_equal(assignment, split_groups(rows, seed=42))
    assert not assignment["split"].equals(split_groups(rows, seed=43)["split"])
    assert assignment.groupby(["split", "label"]).size().to_dict() == {
        ("train", 0): 42, ("train", 1): 42,
        ("validation", 0): 9, ("validation", 1): 9,
        ("test", 0): 9, ("test", 1): 9,
    }
    assert set(check_split_overlap(assignment, ["group_id"])["group_id"].values()) == {0}


def test_small_feasible_dataset_places_both_classes_in_each_split():
    rows = pd.DataFrame({"group_id": range(6), "label": [0, 0, 0, 1, 1, 1]})
    assignment = split_groups(rows, seed=42)
    assert assignment.groupby("split")["label"].nunique().to_dict() == {
        "train": 2, "validation": 2, "test": 2,
    }


@pytest.mark.parametrize("key", ["group_id", "duplicate_key", "hostname"])
def test_overlap_check_rejects_leaked_keys(key):
    rows = pd.DataFrame({"split": ["train", "validation", "test"], key: ["shared", "unique", "shared"]})
    with pytest.raises(ValueError, match=f"Cross-split overlap for {key}"):
        check_split_overlap(rows, [key])
