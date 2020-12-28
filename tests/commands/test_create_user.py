from opencve.commands.create_user import create_user
from opencve.models.users import User


def test_create_user_no_parameters(app):
    runner = app.test_cli_runner()
    result = runner.invoke(create_user, [])

    assert result.exit_code == 2
    assert "Usage: create-user [OPTIONS] USERNAME EMAIL PASSWORD" in result.output


def test_create_user_wrong_parameters(app):
    runner = app.test_cli_runner()

    result = runner.invoke(create_user, ["john"])
    assert result.exit_code == 2
    assert "Missing argument 'EMAIL'" in result.output

    result = runner.invoke(create_user, ["john", "john@domain.com"])
    assert result.exit_code == 2
    assert "Missing argument 'PASSWORD'" in result.output

    result = runner.invoke(
        create_user, ["john", "john@domain.com", "password", "--foo"]
    )
    assert result.exit_code == 2
    assert "Error: no such option: --foo" in result.output


def test_create_simple_user(app):
    runner = app.test_cli_runner()

    result = runner.invoke(create_user, ["john", "john@domain.com", "password"])
    assert result.exit_code == 0
    assert "[*] User john created." in result.output

    user = User.query.first()
    assert user.username == "john"
    assert user.email == "john@domain.com"
    assert not user.admin


def test_create_admin(app):
    runner = app.test_cli_runner()

    result = runner.invoke(
        create_user, ["john", "john@domain.com", "password", "--admin"]
    )
    assert result.exit_code == 0
    assert "[*] User john created." in result.output

    user = User.query.first()
    assert user.username == "john"
    assert user.email == "john@domain.com"
    assert user.admin
