"""Bounded WAFv2 rule *configuration* evidence, never request contents or enforcement proof.

Do not serialize raw WebACL, Rule.Statement, match values, custom headers, tokens,
action response data or arbitrary rule names. The summaries are intentionally
insufficient to infer product-level WAF PASS/FAIL.
"""
from __future__ import annotations

from collections import Counter

ALLOWED_ACTIONS = frozenset({'Allow', 'Block', 'Count', 'Captcha', 'Challenge'})
ALLOWED_OVERRIDES = frozenset({'Count', 'None'})
GROUP_STATEMENTS = frozenset({'ManagedRuleGroupStatement', 'RuleGroupReferenceStatement'})
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
    # A union with additional/unknown keys cannot be treated as a single
    # verified alternative; fail closed against future SDK schema changes.
    if len(value) != 1:
        return None
    key = next(iter(value))
    return key if key in allowed else None


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
        # WAFv2 Rule contract uses OverrideAction for referenced rule
        # groups, Action for a standalone statement. A missing, invalid, or
        # contradictory action must never produce VERIFIED_SUMMARY.
        expected_override = statement in GROUP_STATEMENTS
        # Presence and validity must be checked separately. A malformed
        # extra Action/OverrideAction cannot disappear as a None parsed value.
        valid_action = (
            ('Action' not in rule and 'OverrideAction' in rule and override is not None)
            if expected_override else
            ('Action' in rule and 'OverrideAction' not in rule and action is not None)
        )
        if statement is None or not valid_action:
            incomplete += 1
            continue
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
