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

.PHONY: add
add:
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
		--site $(SITE) \
		--username $(USERNAME)

.PHONY: update
update:
	$(PYTHON) $(MAIN) update \
		--user $(USER) \
		--master-password $(MASTER) \
		--site $(SITE) \
		--username $(USERNAME) \
		--new-password $(NEW_PASSWORD)

.PHONY: retrieve-after-update
retrieve-after-update:
	$(PYTHON) $(MAIN) retrieve \
		--user $(USER) \
		--master-password $(MASTER) \
		--site $(SITE) \
		--username $(USERNAME)

.PHONY: test-flow
test-flow: create-user add retrieve update retrieve-after-update