#!/usr/bin/env python3
"""Create plain-language security passports from signed macOS app metadata."""

from __future__ import annotations

import argparse
import asyncio
import plistlib
import re
import subprocess
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


CODESIGN = "/usr/bin/codesign"
COMMAND_TIMEOUT_SECONDS = 20
SUMMARY_LIMIT = 400
FORBIDDEN_VERDICT = re.compile(
    r"\b(?:safe|secure|unsafe|insecure|malicious|benign|trusted|untrusted|risky|risk)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class EntitlementMeaning:
    category: str
    description: str
    hardening_exception: bool = False


# Descriptions are deliberately narrow paraphrases of Apple's entitlement
# documentation. Unknown and private keys are never interpreted.
ENTITLEMENT_REFERENCE: dict[str, EntitlementMeaning] = {
    "com.apple.security.app-sandbox": EntitlementMeaning(
        "sandbox", "Uses App Sandbox containment."
    ),
    "com.apple.security.network.client": EntitlementMeaning(
        "network", "May initiate outgoing network connections."
    ),
    "com.apple.security.network.server": EntitlementMeaning(
        "network", "May listen for incoming network connections."
    ),
    "com.apple.security.files.user-selected.read-only": EntitlementMeaning(
        "files", "May read files explicitly selected by the user."
    ),
    "com.apple.security.files.user-selected.read-write": EntitlementMeaning(
        "files", "May read and write files explicitly selected by the user."
    ),
    "com.apple.security.files.user-selected.executable": EntitlementMeaning(
        "files", "May write executable files in locations selected by the user."
    ),
    "com.apple.security.files.downloads.read-only": EntitlementMeaning(
        "files", "May read the user's Downloads folder."
    ),
    "com.apple.security.files.downloads.read-write": EntitlementMeaning(
        "files", "May read and write the user's Downloads folder."
    ),
    "com.apple.security.device.camera": EntitlementMeaning(
        "devices", "Declares camera access; user consent may still be required."
    ),
    "com.apple.security.device.audio-input": EntitlementMeaning(
        "devices", "Declares audio-input access; user consent may still be required."
    ),
    "com.apple.security.device.usb": EntitlementMeaning(
        "devices", "May communicate with USB devices."
    ),
    "com.apple.security.device.bluetooth": EntitlementMeaning(
        "devices", "May communicate with Bluetooth devices."
    ),
    "com.apple.security.personal-information.addressbook": EntitlementMeaning(
        "personal-data", "Declares access to contacts; user consent may still be required."
    ),
    "com.apple.security.personal-information.calendars": EntitlementMeaning(
        "personal-data", "Declares access to calendars; user consent may still be required."
    ),
    "com.apple.security.personal-information.location": EntitlementMeaning(
        "personal-data", "Declares location access; user consent may still be required."
    ),
    "com.apple.security.personal-information.photos-library": EntitlementMeaning(
        "personal-data", "Declares photo-library access; user consent may still be required."
    ),
    "com.apple.security.automation.apple-events": EntitlementMeaning(
        "automation", "May send Apple events to automate other applications."
    ),
    "com.apple.security.print": EntitlementMeaning(
        "devices", "May use the macOS printing system."
    ),
    "com.apple.security.application-groups": EntitlementMeaning(
        "shared-data", "May share an application-group container with related components."
    ),
    "keychain-access-groups": EntitlementMeaning(
        "shared-data", "Declares keychain access groups shared with authorized components."
    ),
    "com.apple.developer.icloud-services": EntitlementMeaning(
        "cloud-services", "Declares one or more iCloud services."
    ),
    "com.apple.developer.icloud-container-identifiers": EntitlementMeaning(
        "cloud-services", "Declares one or more iCloud containers."
    ),
    "com.apple.developer.ubiquity-container-identifiers": EntitlementMeaning(
        "cloud-services", "Declares one or more iCloud document containers."
    ),
    "aps-environment": EntitlementMeaning(
        "notifications", "Declares an Apple Push Notification service environment."
    ),
    "com.apple.developer.usernotifications.communication": EntitlementMeaning(
        "notifications", "May provide communication notifications."
    ),
    "com.apple.developer.system-extension.install": EntitlementMeaning(
        "system-extension", "May install system extensions."
    ),
    "com.apple.developer.networking.networkextension": EntitlementMeaning(
        "system-extension", "Declares one or more Network Extension capabilities."
    ),
    "com.apple.developer.endpoint-security.client": EntitlementMeaning(
        "system-extension", "May use the Endpoint Security client API."
    ),
    "com.apple.security.get-task-allow": EntitlementMeaning(
        "debugging", "Allows a debugger to attach to the application."
    ),
    "com.apple.security.cs.debugger": EntitlementMeaning(
        "debugging", "May act as a debugger and obtain task ports for other processes."
    ),
    "com.apple.security.cs.allow-jit": EntitlementMeaning(
        "code-execution", "May create writable and executable memory using MAP_JIT.", True
    ),
    "com.apple.security.cs.allow-unsigned-executable-memory": EntitlementMeaning(
        "code-execution", "May create unsigned executable memory.", True
    ),
    "com.apple.security.cs.disable-library-validation": EntitlementMeaning(
        "code-execution", "May load code that is not signed by Apple or the same team.", True
    ),
    "com.apple.security.cs.allow-dyld-environment-variables": EntitlementMeaning(
        "code-execution", "Allows dynamic-linker environment variables to affect the process.", True
    ),
    "com.apple.security.cs.disable-executable-page-protection": EntitlementMeaning(
        "code-execution", "Disables executable-memory protections for the process.", True
    ),
}

IDENTITY_ENTITLEMENTS = {
    "application-identifier",
    "com.apple.application-identifier",
    "com.apple.developer.team-identifier",
    "com.apple.developer.icloud-container-environment",
}


@dataclass
class Capability:
    key: str
    value: Any
    meaning: EntitlementMeaning


@dataclass
class AppPassport:
    path: Path
    name: str
    version: str
    bundle_identifier: str
    executable: str
    signature_valid: bool
    signer: str
    team_identifier: str
    runtime_version: str
    sandbox_enabled: bool
    capabilities: list[Capability]
    hardening_exceptions: list[Capability]
    unknown_entitlements: list[tuple[str, Any]]
    warnings: list[str]

    @property
    def categories(self) -> list[str]:
        categories = {capability.meaning.category for capability in self.capabilities}
        if self.sandbox_enabled:
            categories.add("sandbox")
        if self.hardening_exceptions:
            categories.add("hardening-exception")
        return sorted(categories)


@dataclass
class ModelExplanation:
    summary: str
    tags: list[str]


class PassportError(Exception):
    """An application could not be inspected."""


def sanitize_text(value: Any, limit: int = 240) -> str:
    """Render untrusted metadata without terminal control characters."""
    raw = str(value)
    rendered: list[str] = []
    for character in raw:
        category = unicodedata.category(character)
        if category.startswith("C"):
            rendered.append(f"\\u{ord(character):04x}")
        else:
            rendered.append(character)
        if sum(len(part) for part in rendered) >= limit:
            rendered.append("...")
            break
    return "".join(rendered)


def format_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        items = [sanitize_text(item, 100) for item in value[:4]]
        if len(value) > 4:
            items.append(f"... ({len(value) - 4} more)")
        return "[" + ", ".join(items) + "]"
    if isinstance(value, dict):
        keys = [sanitize_text(key, 80) for key in list(value)[:4]]
        if len(value) > 4:
            keys.append(f"... ({len(value) - 4} more keys)")
        return "{" + ", ".join(keys) + "}"
    return sanitize_text(value)


def run_command(arguments: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            list(arguments),
            capture_output=True,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise PassportError(f"command timed out after {COMMAND_TIMEOUT_SECONDS} seconds") from error
    except OSError as error:
        raise PassportError(f"could not run {arguments[0]}: {error}") from error


def parse_codesign_fields(stderr: bytes) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for raw_line in stderr.decode("utf-8", errors="replace").splitlines():
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        fields.setdefault(key, []).append(value)
    return fields


def entitlement_is_active(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return value is not None


def scan_app(app_path: Path) -> AppPassport:
    info_path = app_path / "Contents" / "Info.plist"
    try:
        info = plistlib.loads(info_path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as error:
        raise PassportError(f"cannot read {info_path}: {error}") from error
    if not isinstance(info, dict):
        raise PassportError(f"{info_path} does not contain a property-list dictionary")

    executable_name = info.get("CFBundleExecutable")
    if not isinstance(executable_name, str) or not executable_name:
        raise PassportError("Info.plist does not declare CFBundleExecutable")
    executable_path = app_path / "Contents" / "MacOS" / executable_name
    if not executable_path.is_file():
        raise PassportError(f"main executable does not exist: {executable_path}")

    display = run_command([CODESIGN, "--display", "--verbose=4", str(executable_path)])
    fields = parse_codesign_fields(display.stderr)
    warnings: list[str] = []
    if display.returncode != 0:
        warnings.append("Code-signing metadata could not be read completely.")

    verification = run_command(
        [CODESIGN, "--verify", "--strict", "--verbose=2", str(executable_path)]
    )
    signature_valid = verification.returncode == 0
    if not signature_valid:
        warnings.append("The main application signature did not verify under strict validation.")

    entitlement_result = run_command(
        [CODESIGN, "--display", "--entitlements", "-", "--xml", str(executable_path)]
    )
    entitlements: dict[str, Any] = {}
    if entitlement_result.returncode == 0 and entitlement_result.stdout.strip():
        try:
            parsed = plistlib.loads(entitlement_result.stdout)
            if isinstance(parsed, dict):
                entitlements = parsed
            else:
                warnings.append("The entitlement property list was not a dictionary.")
        except plistlib.InvalidFileException:
            warnings.append("The entitlement property list could not be parsed.")
    elif entitlement_result.returncode != 0:
        warnings.append("Embedded entitlements could not be read.")

    capabilities: list[Capability] = []
    hardening_exceptions: list[Capability] = []
    unknown: list[tuple[str, Any]] = []
    for raw_key, value in sorted(entitlements.items(), key=lambda item: str(item[0])):
        key = str(raw_key)
        if key in IDENTITY_ENTITLEMENTS or not entitlement_is_active(value):
            continue
        meaning = ENTITLEMENT_REFERENCE.get(key)
        if meaning is None:
            unknown.append((key, value))
            continue
        capability = Capability(key, value, meaning)
        if meaning.hardening_exception:
            hardening_exceptions.append(capability)
        elif key != "com.apple.security.app-sandbox":
            capabilities.append(capability)

    name = info.get("CFBundleDisplayName") or info.get("CFBundleName") or app_path.stem
    bundle_identifier = info.get("CFBundleIdentifier") or first_field(fields, "Identifier") or "not declared"
    return AppPassport(
        path=app_path,
        name=sanitize_text(name),
        version=sanitize_text(info.get("CFBundleShortVersionString") or "not declared"),
        bundle_identifier=sanitize_text(bundle_identifier),
        executable=sanitize_text(executable_name),
        signature_valid=signature_valid,
        signer=sanitize_text(first_field(fields, "Authority") or "not declared"),
        team_identifier=sanitize_text(first_field(fields, "TeamIdentifier") or "not declared"),
        runtime_version=sanitize_text(first_field(fields, "Runtime Version") or "not declared"),
        sandbox_enabled=entitlements.get("com.apple.security.app-sandbox") is True,
        capabilities=capabilities,
        hardening_exceptions=hardening_exceptions,
        unknown_entitlements=unknown,
        warnings=warnings,
    )


def first_field(fields: dict[str, list[str]], key: str) -> str | None:
    values = fields.get(key)
    return values[0] if values else None


def collect_apps(inputs: Sequence[str]) -> tuple[list[Path], list[str]]:
    apps: dict[Path, Path] = {}
    errors: list[str] = []
    for raw_input in inputs:
        candidate = Path(raw_input).expanduser()
        if not candidate.exists():
            errors.append(f"input does not exist: {sanitize_text(candidate)}")
            continue
        if candidate.is_dir() and candidate.suffix.lower() == ".app":
            resolved = candidate.resolve()
            apps[resolved] = resolved
            continue
        if candidate.is_dir():
            children = sorted(
                (
                    child
                    for child in candidate.iterdir()
                    if child.is_dir() and child.suffix.lower() == ".app"
                ),
                key=lambda child: child.name.casefold(),
            )
            if not children:
                errors.append(f"directory contains no immediate .app children: {sanitize_text(candidate)}")
            for child in children:
                resolved = child.resolve()
                apps[resolved] = resolved
            continue
        errors.append(f"input is neither an .app bundle nor a directory: {sanitize_text(candidate)}")
    return sorted(apps.values(), key=lambda path: str(path).casefold()), errors


def trusted_prompt(passport: AppPassport, corrective: bool = False) -> str:
    facts = [capability.meaning.description for capability in passport.capabilities]
    facts.extend(capability.meaning.description for capability in passport.hardening_exceptions)
    facts.insert(
        0,
        "App Sandbox is enabled." if passport.sandbox_enabled else "No App Sandbox entitlement is declared.",
    )
    if passport.unknown_entitlements:
        facts.append(
            f"There are {len(passport.unknown_entitlements)} unknown entitlement keys whose meanings were not interpreted."
        )
    if not facts:
        facts.append("No interpreted security-relevant capabilities were found.")

    allowed_tags = passport.categories
    correction = (
        "A previous response failed validation. Do not use any safety, trust, malware, or risk verdict."
        if corrective
        else ""
    )
    fact_lines = "\n".join(f"- {fact}" for fact in facts)
    tag_text = ", ".join(allowed_tags) if allowed_tags else "none"
    return f"""Translate these deterministic macOS metadata facts into neutral language.
{correction}
Begin the summary exactly with "The signed metadata declares".
Write no more than two short sentences. Describe only declared capabilities and exceptions.
Do not claim actual behavior, user consent, safety, trust, malware status, or risk.
Select zero to four tags, using only this allowed set: {tag_text}

Facts:
{fact_lines}
"""


def validate_explanation(result: Any, allowed_tags: set[str]) -> ModelExplanation:
    summary = sanitize_text(getattr(result, "summary", ""), SUMMARY_LIMIT + 20).strip()
    raw_tags = getattr(result, "tags", [])
    if not summary or len(summary) > SUMMARY_LIMIT:
        raise ValueError("summary is empty or too long")
    if not summary.startswith("The signed metadata declares"):
        raise ValueError("summary does not attribute its claims to signed metadata")
    if FORBIDDEN_VERDICT.search(summary):
        raise ValueError("summary contains a prohibited security verdict")
    sentence_marks = len(re.findall(r"[.!?](?:\s|$)", summary))
    if sentence_marks > 2:
        raise ValueError("summary contains more than two sentences")
    if not isinstance(raw_tags, list) or len(raw_tags) > 4:
        raise ValueError("tag list is invalid")
    tags = [sanitize_text(tag, 40).strip().lower() for tag in raw_tags]
    if len(tags) != len(set(tags)) or any(tag not in allowed_tags for tag in tags):
        raise ValueError("tags are duplicated or outside the deterministic category set")
    return ModelExplanation(summary=summary, tags=tags)


def load_foundation_models() -> tuple[Any, type[Any]]:
    import apple_fm_sdk as fm

    @fm.generable("A neutral plain-language explanation of signed macOS app metadata")
    class PassportExplanation:
        summary: str = fm.guide(
            "One or two short sentences using only supplied facts and no security verdict"
        )
        tags: list[str] = fm.guide(
            "Zero to four short tags chosen only from the allowed tags in the prompt"
        )

    return fm, PassportExplanation


async def explain_passport(
    fm: Any,
    explanation_type: type[Any],
    model: Any,
    passport: AppPassport,
) -> tuple[ModelExplanation | None, str | None]:
    last_error = "generation failed"
    for attempt in range(2):
        session = fm.LanguageModelSession(
            model=model,
            instructions=(
                "You rewrite supplied signed metadata as concise neutral prose. "
                "Begin the summary exactly with 'The signed metadata declares'. "
                "Never add capabilities, infer behavior, or make safety, trust, malware, or risk verdicts."
            ),
        )
        try:
            result = await session.respond(
                trusted_prompt(passport, corrective=attempt == 1),
                generating=explanation_type,
            )
            return validate_explanation(result, set(passport.categories)), None
        except Exception as error:  # SDK errors share a broad public base hierarchy.
            last_error = sanitize_text(error, 180)
    return None, last_error


def print_capability(capability: Capability) -> None:
    print(f"  [{capability.meaning.category}] {sanitize_text(capability.key)}")
    print(f"    {capability.meaning.description}")
    if capability.value is not True:
        print(f"    value: {format_value(capability.value)}")


def render_passport(
    passport: AppPassport,
    explanation: ModelExplanation | None,
    explanation_error: str | None,
) -> None:
    print("=" * 78)
    print("APP SECURITY PASSPORT")
    print("=" * 78)
    print(f"App:        {passport.name}")
    print(f"Version:    {passport.version}")
    print(f"Path:       {sanitize_text(passport.path, 500)}")
    print(f"Bundle ID:  {passport.bundle_identifier}")
    print(f"Executable: {passport.executable}")
    print()
    print("SIGNATURE")
    print(f"  Verified: {'yes' if passport.signature_valid else 'no'}")
    print(f"  Signer:   {passport.signer}")
    print(f"  Team ID:  {passport.team_identifier}")
    print(f"  Runtime:  {passport.runtime_version}")
    print()
    print("APP SANDBOX")
    print(f"  {'enabled' if passport.sandbox_enabled else 'not declared'}")
    print()
    print("CAPABILITIES")
    if passport.capabilities:
        for capability in passport.capabilities:
            print_capability(capability)
    else:
        print("  none interpreted")
    print()
    print("HARDENING EXCEPTIONS")
    if passport.hardening_exceptions:
        for capability in passport.hardening_exceptions:
            print_capability(capability)
    else:
        print("  none interpreted")
    print()
    print("UNKNOWN ENTITLEMENTS")
    if passport.unknown_entitlements:
        for key, value in passport.unknown_entitlements:
            print(f"  {sanitize_text(key)} = {format_value(value)}")
    else:
        print("  none")
    print()
    print("MODEL TAGS")
    if explanation and explanation.tags:
        print("  " + ", ".join(explanation.tags))
    elif explanation:
        print("  none")
    else:
        print("  unavailable")
    print()
    print("PLAIN-LANGUAGE EXPLANATION")
    if explanation:
        print(f"  {explanation.summary}")
    else:
        print("  unavailable; the deterministic facts above remain valid")
        if explanation_error:
            print(f"  reason: {sanitize_text(explanation_error)}")
    if passport.warnings:
        print()
        print("WARNINGS")
        for warning in passport.warnings:
            print(f"  - {warning}")
    print()
    print("Entitlements describe signed capabilities, not behavior, consent, or trust.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Explain signed macOS app metadata with Apple's on-device foundation model."
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        metavar="APP_OR_DIRECTORY",
        help="an explicit .app bundle or a directory whose immediate .app children should be scanned",
    )
    return parser


async def async_main(arguments: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(arguments)
    apps, input_errors = collect_apps(args.inputs)
    failed = bool(input_errors)
    for error in input_errors:
        print(f"error: {error}", file=sys.stderr)
    if not apps:
        return 1

    model: Any | None = None
    fm: Any | None = None
    explanation_type: type[Any] | None = None
    model_error: str | None = None
    try:
        fm, explanation_type = load_foundation_models()
        model = fm.SystemLanguageModel()
        available, reason = model.is_available()
        if not available:
            model_error = f"Foundation Models unavailable: {sanitize_text(reason)}"
            failed = True
    except Exception as error:
        model_error = f"Foundation Models SDK unavailable: {sanitize_text(error)}"
        failed = True

    for index, app_path in enumerate(apps):
        if index:
            print()
        try:
            passport = scan_app(app_path)
        except PassportError as error:
            print(f"error: {sanitize_text(app_path)}: {sanitize_text(error)}", file=sys.stderr)
            failed = True
            continue

        explanation: ModelExplanation | None = None
        explanation_error = model_error
        if model is not None and fm is not None and explanation_type is not None and model_error is None:
            explanation, explanation_error = await explain_passport(
                fm, explanation_type, model, passport
            )
            if explanation is None:
                failed = True
        render_passport(passport, explanation, explanation_error)
        if passport.warnings:
            failed = True

    return 1 if failed else 0


def main() -> int:
    try:
        return asyncio.run(async_main())
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
