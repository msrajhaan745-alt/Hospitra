"""Command-line administration.

    python -m app.seed.cli seed                         # idempotent: creates only what is missing
    python -m app.seed.cli reset [--yes]                # deletes all data (users are kept) and reseeds
    python -m app.seed.cli create-user --username alice --display-name "Alice" --role Admin
                                                        # prompts for the password (never pass it as an argument)
"""

from __future__ import annotations

import argparse
import getpass
import sys

from pydantic import ValidationError

from app.core.config import settings
from app.core.constants import Role
from app.core.exceptions import AppError
from app.db.session import SessionLocal
from app.schemas.user import UserCreate
from app.seed.seeder import reset_data, seed_all
from app.services import user_service


def _create_user(args: argparse.Namespace) -> int:
    password = getpass.getpass("Password: ")
    if password != getpass.getpass("Repeat password: "):
        print("Passwords do not match.")
        return 1
    try:
        payload = UserCreate(username=args.username, display_name=args.display_name, role=args.role, password=password)
    except ValidationError as exc:
        for err in exc.errors():
            print(f"  {'.'.join(str(p) for p in err['loc'])}: {err['msg']}")
        return 1
    with SessionLocal() as db:
        try:
            user = user_service.create_user(db, payload, actor="cli")
        except AppError as exc:
            print(exc.message)
            return 1
    print(f"Created {user.role.value} account '{user.username}'.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.seed.cli", description="Hospitra administration.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("seed", help="Create any missing data (safe to re-run).")
    reset = sub.add_parser("reset", help="Delete all data (user accounts are kept) and reseed.")
    reset.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    create = sub.add_parser("create-user", help="Create a user account (password is prompted).")
    create.add_argument("--username", required=True)
    create.add_argument("--display-name", required=True)
    create.add_argument("--role", required=True, choices=[r.value for r in Role])
    args = parser.parse_args(argv)

    print(f"Database: {settings.database_url}")
    if args.command == "create-user":
        return _create_user(args)
    with SessionLocal() as db:
        if args.command == "seed":
            report = seed_all(db)
            print("Seed complete." if report.total_created else "Seed complete — nothing to add (already seeded).")
        else:
            if not args.yes:
                answer = input("This deletes all Hospitra data (user accounts are kept) and reseeds. Type RESET to continue: ")
                if answer.strip() != "RESET":
                    print("Aborted.")
                    return 1
            report = reset_data(db, actor=settings.operator_actor)
            print("Reset complete.")
    for key, value in sorted(report.created.items()):
        print(f"  created {key}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
