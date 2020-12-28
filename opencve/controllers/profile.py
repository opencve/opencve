from flask import current_app as app
from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

# from flask_user import emails

from opencve.controllers.main import main
from opencve.extensions import db
from opencve.forms import (
    ChangeEmailForm,
    ChangePasswordForm,
    FiltersNotificationForm,
    MailNotificationsForm,
)


@main.route("/account/subscriptions", methods=["GET"])
@login_required
def subscriptions():
    return render_template("profiles/subscriptions.html")


@main.route("/account/notifications", methods=["GET", "POST"])
@login_required
def notifications():
    mail_notifications_form = MailNotificationsForm(
        obj=current_user,
        enable="yes" if current_user.enable_notifications else "no",
        frequency=current_user.frequency_notifications.code,
    )

    filters = current_user.filters_notifications or {"event_types": [], "cvss": 0}
    filters_notifications_form = FiltersNotificationForm(
        obj=current_user,
        new_cve=True if "new_cve" in filters["event_types"] else False,
        references=True if "references" in filters["event_types"] else False,
        cvss=True if "cvss" in filters["event_types"] else False,
        cpes=True if "cpes" in filters["event_types"] else False,
        summary=True if "summary" in filters["event_types"] else False,
        cwes=True if "cwes" in filters["event_types"] else False,
        cvss_score=filters["cvss"],
    )

    if request.method == "POST":
        form_name = request.form["form-name"]

        if (
            form_name == "mail_notifications_form"
            and mail_notifications_form.validate()
        ):
            current_user.enable_notifications = (
                True if mail_notifications_form.enable.data == "yes" else False
            )
            current_user.frequency_notifications = (
                mail_notifications_form.frequency.data
            )
            db.session.commit()

            flash(
                "Your notifications setting has been changed successfully.", "success"
            )
            return redirect(url_for("main.notifications"))

        if (
            form_name == "filters_notifications_form"
            and filters_notifications_form.validate()
        ):
            filters = {
                "event_types": [],
                "cvss": filters_notifications_form.cvss_score.data,
            }

            for typ in ["new_cve", "references", "cvss", "cpes", "cwes", "summary"]:
                if getattr(filters_notifications_form, typ).data:
                    filters["event_types"].append(typ)

            current_user.filters_notifications = filters
            db.session.commit()

            flash(
                "Your notifications setting has been changed successfully.", "success"
            )
            return redirect(url_for("main.notifications"))

    return render_template(
        "profiles/notifications.html",
        mail_notifications_form=mail_notifications_form,
        filters_notifications_form=filters_notifications_form,
    )
