PYTHON := py
MAIN := run.py

USER := test_user
MASTER := test_master_password

SITE := example.com
USERNAME := john_doe
PASSWORD := 123456
NEW_PASSWORD := 654321

SENDER   := test_user
RECEIVER := test_receiver
RECEIVER_MASTER := receiver_master_password

HANDSHAKE_FILE := transfer/handshake.json
PACKAGE_FILE   := transfer/package.json

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
	-$(PYTHON) $(MAIN) retrieve \
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

.PHONY: create-receiver
create-receiver:
	-$(PYTHON) $(MAIN) init-user \
		--user $(RECEIVER) \
		--master-password $(RECEIVER_MASTER)

.PHONY: prepare-import
prepare-import:
	$(PYTHON) $(MAIN) prepare-import \
		--recipient $(RECEIVER) \
		--sender    $(SENDER) \
		--out       $(HANDSHAKE_FILE)

.PHONY: export-vault
export-vault:
	$(PYTHON) $(MAIN) export \
		--sender            $(SENDER) \
		--master-password   $(MASTER) \
		--recipient-session $(HANDSHAKE_FILE) \
		--out               $(PACKAGE_FILE)

.PHONY: import-vault
import-vault:
	$(PYTHON) $(MAIN) import \
		--recipient       $(RECEIVER) \
		--sender          $(SENDER) \
		--master-password $(RECEIVER_MASTER) \
		--package         $(PACKAGE_FILE)

.PHONY: test-transfer
test-transfer:
	$(MAKE) create-receiver
	$(MAKE) prepare-import
	$(MAKE) export-vault
	$(MAKE) import-vault
	@echo "--- Verify receiver vault ---"
	$(PYTHON) $(MAIN) verify --user $(RECEIVER)
	@echo "--- List receiver credentials ---"
	$(PYTHON) $(MAIN) list \
		--user            $(RECEIVER) \
		--master-password $(RECEIVER_MASTER)

.PHONY: test-flow
test-crud:
	$(MAKE) create-user
	$(MAKE) add-credential
	$(MAKE) retrieve
	$(MAKE) retrieve-failure
	$(MAKE) update
	$(MAKE) retrieve
	$(MAKE) delete-credential
	$(MAKE) retrieve
	$(MAKE) add-credential
	$(MAKE) retrieve

.PHONY: test-all
test-all: test-crud test-transfer
	