from opencve.extensions import db
from opencve.models.users import User
from opencve.admin import UserModelView
import pytest


@pytest.mark.freeze_time
def test_on_model_change_create_form(app, create_user, freezer):
    user = create_user("opencve")
    object = UserModelView(User, db.session)
    form = UserModelView.get_create_form(object)
    form.create_password.data = "create_password"
    freezer.move_to("2021-07-13")
    object.on_model_change(form, user, True)
    db.session.commit()
    assert app.user_manager.verify_password("create_password", user.password) == True
    assert user.email_confirmed_at.strftime("%Y-%m-%d") == "2021-07-13"


def test_on_model_change_edit_form(app, create_user):
    user = create_user("app")
    object = UserModelView(User, db.session)
    form = UserModelView.get_edit_form(object)
    form.edit_password.data = "edit_password"
    object._on_model_change(form, user, False)
    db.session.commit()
    assert app.user_manager.verify_password("edit_password", user.password) == True
