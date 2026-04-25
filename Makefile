PYTHON := py
MAIN := run.py

USER := test_user
MASTER := test_master_password

SITE := example.com
USERNAME := john_doe
PASSWORD := 123456
NEW_PASSWORD := 654321

.PHONY: create-user
create-user:
	-$(PYTHON) $(MAIN) init-user \
		--user $(USER) \
		--master-password $(MASTER)

.PHONY: add-credential
add-credential:
	-$(PYTHON) $(MAIN) add \
		--user $(USER) \
		--master-password $(MASTER) \
		--site $(SITE) \
		--username $(USERNAME) \
		--password $(PASSWORD)

.PHONY: retrieve
retrieve:
	$(PYTHON) $(MAIN) retrieve \
		--user $(USER) \
		--master-password $(MASTER) \
		--site $(SITE)

.PHONY: retrieve-failure
retrieve-failure:
	-$(PYTHON) $(MAIN) retrieve \
		--user $(USER) \
		--master-password $(MASTER) \
		--site non_existent_site

.PHONY: update
update:
	$(PYTHON) $(MAIN) update \
		--user $(USER) \
		--master-password $(MASTER) \
		--site $(SITE) \
		--username $(USERNAME) \
		--new-password $(NEW_PASSWORD)

.PHONY: delete-credential
delete-credential:
	-$(PYTHON) $(MAIN) delete \
		--user $(USER) \
		--master-password $(MASTER) \
		--site $(SITE) \
		--username $(USERNAME)

.PHONY: test-flow
test-flow:
	$(MAKE) create-user
	$(MAKE) add-credential
	$(MAKE) retrieve
	$(MAKE) retrieve-failure
	$(MAKE) update
	$(MAKE) retrieve
	$(MAKE) delete-credential
	$(MAKE) retrieve