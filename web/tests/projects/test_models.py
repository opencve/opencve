def test_project_model(create_user, create_organization, create_project):
    user = create_user(username="user1")
    org = create_organization(name="organization1", user=user)
    project = create_project(
        name="project1",
        organization=org,
        description="my description",
        vendors=["vendor1", "vendor2"],
        products=["product1", "product2"],
    )

    assert project.name == "project1"
    assert project.description == "my description"
    assert project.active is True
    assert project.subscriptions == {
        "vendors": ["vendor1", "vendor2"],
        "products": ["product1", "product2"],
    }
    assert project.organization == org
    assert project.get_absolute_url() == "/org/organization1/projects/project1"
    assert project.subscriptions_count == 4
