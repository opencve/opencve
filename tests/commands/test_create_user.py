from opencve.commands.create_user import create_user
from opencve.models.users import User


def test_create_user_no_parameters(app):
    runner = app.test_cli_runner()
    result = runner.invoke(create_user, [])

    assert result.exit_code == 2
    assert "Usage: create-user [OPTIONS] USERNAME EMAIL" in result.output


def test_create_user_wrong_parameters(app):
    runner = app.test_cli_runner()

    result = runner.invoke(create_user, ["john"])
    assert result.exit_code == 2
    assert "Missing argument 'EMAIL'" in result.output

    result = runner.invoke(create_user, ["john", "john@domain.com", "--foo"])
    assert result.exit_code == 2
    assert "Error: no such option: --foo" in result.output


def test_create_simple_user(app):
    runner = app.test_cli_runner()

    result = runner.invoke(
        create_user, ["john", "john@domain.com"], input="password\npassword\n"
    )
    assert result.exit_code == 0
    assert "[*] User john created." in result.output

    user = User.query.first()
    assert user.username == "john"
    assert user.email == "john@domain.com"
    assert not user.admin


def test_create_admin(app):
    runner = app.test_cli_runner()

    result = runner.invoke(
        create_user,
        ["john", "john@domain.com", "--admin"],
        input="password\npassword\n",
    )
    assert result.exit_code == 0
    assert "[*] User john created." in result.output

    user = User.query.first()
    assert user.username == "john"
    assert user.email == "john@domain.com"
    assert user.admin


def test_create_user_already_exists(app):
    runner = app.test_cli_runner()

    result = runner.invoke(
        create_user, ["john", "john@domain.com"], input="password\npassword\n"
    )
    assert result.exit_code == 0
    assert "[*] User john created." in result.output

    result = runner.invoke(
        create_user, ["john", "john@domain.com"], input="password\npassword\n"
    )
    assert result.exit_code == 2
    assert "Error: Invalid value for username: john already exists." in result.output

    result = runner.invoke(
        create_user, ["john2", "john@domain.com"], input="password\npassword\n"
    )
    assert result.exit_code == 2
    assert (
        "Error: Invalid value for email: john@domain.com already exists."
        in result.output
    )
