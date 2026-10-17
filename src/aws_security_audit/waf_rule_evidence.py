"""Bounded WAFv2 rule *configuration* evidence, never request contents or enforcement proof.

Do not serialize raw WebACL, Rule.Statement, match values, custom headers, tokens,
action response data or arbitrary rule names. The summaries are intentionally
insufficient to infer product-level WAF PASS/FAIL.
"""
from __future__ import annotations

from collections import Counter

ALLOWED_ACTIONS = frozenset({'Allow', 'Block', 'Count', 'Captcha', 'Challenge'})
ALLOWED_OVERRIDES = frozenset({'Count', 'None'})
ALLOWED_STATEMENTS = frozenset({
    'ManagedRuleGroupStatement', 'RuleGroupReferenceStatement',
    'RateBasedStatement', 'GeoMatchStatement', 'IPSetReferenceStatement',
    'ByteMatchStatement', 'RegexMatchStatement', 'RegexPatternSetReferenceStatement',
    'SqliMatchStatement', 'XssMatchStatement', 'SizeConstraintStatement',
    'LabelMatchStatement', 'AsnMatchStatement', 'AndStatement', 'OrStatement',
    'NotStatement',
})


def _single_allowed_key(value, allowed):
    if not isinstance(value, dict):
        return None
    keys = [key for key in value if key in allowed]
    return keys[0] if len(keys) == 1 else None


def web_acl_rule_summary(acl):
    """Return allowlisted rule-type/action counts only; incomplete is UNKNOWN."""
    if not isinstance(acl, dict):
        return {'state': 'UNVERIFIED_WEB_ACL'}
    rules = acl.get('Rules')
    if not isinstance(rules, list):
        return {'state': 'UNVERIFIED_RULE_LIST'}
    default_action = _single_allowed_key(acl.get('DefaultAction'), ALLOWED_ACTIONS)
    if default_action not in ('Allow', 'Block'):
        return {'state': 'UNVERIFIED_DEFAULT_ACTION'}
    actions = Counter()
    statements = Counter()
    overrides = Counter()
    incomplete = 0
    for rule in rules:
        if not isinstance(rule, dict):
            incomplete += 1
            continue
        statement = _single_allowed_key(rule.get('Statement'), ALLOWED_STATEMENTS)
        action = _single_allowed_key(rule.get('Action'), ALLOWED_ACTIONS)
        override = _single_allowed_key(rule.get('OverrideAction'), ALLOWED_OVERRIDES)
        if statement is None:
            incomplete += 1
        else:
            statements[statement] += 1
        if action is not None:
            actions[action] += 1
        if override is not None:
            overrides[override] += 1
    return {
        'state': 'VERIFIED_SUMMARY' if incomplete == 0 else 'PARTIAL_RULE_SUMMARY',
        'rule_count': len(rules),
        'default_action': default_action,
        'statement_type_counts': dict(sorted(statements.items())),
        'explicit_rule_action_counts': dict(sorted(actions.items())),
        'rule_override_counts': dict(sorted(overrides.items())),
        'unclassified_rule_count': incomplete,
        'scope_limit': (
            'Top-level statements and explicit outer actions only. '
            'Nested rules, managed-rule configuration and exceptions, actual '
            'request routing, logging, propagation and effective blocking unverified.'
        ),
    }
