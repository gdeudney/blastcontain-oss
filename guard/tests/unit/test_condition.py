"""The safe, eval-free condition evaluator must be both correct and locked down."""
import pytest

from blastcontain_guard.condition import ConditionError, compile_condition


class TestMatching:
    def test_membership(self):
        c = compile_condition("tool_name in ['a', 'b']")
        assert c.matches({"tool_name": "a"})
        assert not c.matches({"tool_name": "c"})

    def test_not_in(self):
        c = compile_condition("not tool_name in ['ok']")
        assert c.matches({"tool_name": "x"})
        assert not c.matches({"tool_name": "ok"})

    def test_attribute_equality(self):
        c = compile_condition("action.type == 'delete'")
        assert c.matches({"action": {"type": "delete"}})
        assert not c.matches({"action": {"type": "read"}})

    def test_missing_field_is_none_not_crash(self):
        c = compile_condition("action.type == 'delete'")
        assert not c.matches({})            # action absent -> None -> no match
        assert not c.matches({"action": {}})  # type absent -> None -> no match

    def test_boolean_combination(self):
        c = compile_condition("action.type == 'send' and not tool_name in ['receipt']")
        assert c.matches({"action": {"type": "send"}, "tool_name": "x"})
        assert not c.matches({"action": {"type": "send"}, "tool_name": "receipt"})

    def test_numeric_ordering(self):
        c = compile_condition("args.count > 5")
        assert c.matches({"args": {"count": 6}})
        assert not c.matches({"args": {"count": 1}})
        assert not c.matches({"args": {}})   # None > 5 is a non-match, not an error

    def test_or(self):
        c = compile_condition("tool_name == 'a' or tool_name == 'b'")
        assert c.matches({"tool_name": "b"})
        assert not c.matches({"tool_name": "c"})


class TestLockdown:
    @pytest.mark.parametrize(
        "expr",
        [
            "os.system('rm -rf /')",     # Call + unknown name
            "__import__('os')",          # Call + dunder name
            "len(tool_name)",            # Call
            "tool_name.__class__",       # dunder attribute
            "1 + 1",                     # arithmetic BinOp
            "foo == 1",                  # unknown root name
            "[x for x in args]",         # comprehension
            "lambda: 1",                 # lambda
            "",                          # empty
        ],
    )
    def test_rejected_at_compile_time(self, expr):
        with pytest.raises(ConditionError):
            compile_condition(expr)

    def test_referenced_names(self):
        c = compile_condition("tool_name == 'x' and action.type == 'y'")
        assert c.referenced_names() == {"tool_name", "action"}
