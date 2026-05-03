PYTHON   := py
MAIN     := run.py
DATA_DIR := data

ifeq ($(OS),Windows_NT)
    RM_DIR = rmdir /s /q
    MKDIR  = mkdir
else
    RM_DIR = rm -rf
    MKDIR  = mkdir -p
endif

USER             := test_user
MASTER           := test_master_password

SENDER           := test_user
RECEIVER         := test_receiver
RECEIVER_MASTER  := receiver_master_password

SITE         := example.com
USERNAME     := john_doe
PASSWORD     := 123456
NEW_PASSWORD := 654321

SITE2        := github.com
USERNAME2    := jane_doe
PASSWORD2    := abcdef

.PHONY: create-user
create-user:
	-$(PYTHON) $(MAIN) init-user \
		--user            $(USER) \
		--master-password $(MASTER)

.PHONY: create-receiver
create-receiver:
	-$(PYTHON) $(MAIN) init-user \
		--user            $(RECEIVER) \
		--master-password $(RECEIVER_MASTER)

.PHONY: add-credential
add-credential:
	-$(PYTHON) $(MAIN) add \
		--user            $(USER) \
		--master-password $(MASTER) \
		--site            $(SITE) \
		--username        $(USERNAME) \
		--password        $(PASSWORD)

.PHONY: add-credential-2
add-credential-2:
	-$(PYTHON) $(MAIN) add \
		--user            $(USER) \
		--master-password $(MASTER) \
		--site            $(SITE2) \
		--username        $(USERNAME2) \
		--password        $(PASSWORD2)

.PHONY: retrieve
retrieve:
	-$(PYTHON) $(MAIN) retrieve \
		--user            $(USER) \
		--master-password $(MASTER) \
		--site            $(SITE)

.PHONY: retrieve-failure
retrieve-failure:
	@echo "--- Expecting a retrieval failure for non-existent site ---"
	-$(PYTHON) $(MAIN) retrieve \
		--user            $(USER) \
		--master-password $(MASTER) \
		--site            non_existent_site

.PHONY: update
update:
	$(PYTHON) $(MAIN) update \
		--user            $(USER) \
		--master-password $(MASTER) \
		--site            $(SITE) \
		--username        $(USERNAME) \
		--new-password    $(NEW_PASSWORD)

.PHONY: delete-credential
delete-credential:
	-$(PYTHON) $(MAIN) delete \
		--user            $(USER) \
		--master-password $(MASTER) \
		--site            $(SITE) \
		--username        $(USERNAME)

.PHONY: list
list:
	$(PYTHON) $(MAIN) list \
		--user            $(USER) \
		--master-password $(MASTER)

.PHONY: verify
verify:
	$(PYTHON) $(MAIN) verify --user $(USER)

.PHONY: verify-receiver
verify-receiver:
	$(PYTHON) $(MAIN) verify --user $(RECEIVER)

.PHONY: export-vault
export-vault:
	$(PYTHON) $(MAIN) export \
		--sender          $(SENDER) \
		--master-password $(MASTER) \
		--receiver        $(RECEIVER)

.PHONY: import-vault
import-vault:
	$(PYTHON) $(MAIN) import \
		--receiver        $(RECEIVER) \
		--sender          $(SENDER) \
		--master-password $(RECEIVER_MASTER)

.PHONY: list-receiver
list-receiver:
	$(PYTHON) $(MAIN) list \
		--user            $(RECEIVER) \
		--master-password $(RECEIVER_MASTER)

.PHONY: clean-data
ifeq ($(OS),Windows_NT)
clean-data:
	@echo Cleaning $(DATA_DIR) on Windows...
	@if exist "$(DATA_DIR)" ( \
		for /d %%i in ("$(DATA_DIR)\*") do rmdir /s /q "%%i" & \
		del /q "$(DATA_DIR)\*" \
	)
else
clean-data:
	@echo Cleaning $(DATA_DIR) on Unix...
	@find $(DATA_DIR) -mindepth 1 -delete
endif

.PHONY: test-crud
test-crud:
	@echo "MODULE 1 - User initialisation"
	$(MAKE) clean-data
	$(MAKE) create-user

	@echo " MODULE 2 - Credential management"
	$(MAKE) add-credential
	$(MAKE) retrieve
	$(MAKE) add-credential-2
	$(MAKE) list
	$(MAKE) update
	$(MAKE) retrieve
	$(MAKE) retrieve-failure
	$(MAKE) delete-credential
	$(MAKE) retrieve-failure
	$(MAKE) list
	$(MAKE) add-credential

	@echo " MODULE 3 - Vault signature verification"
	$(MAKE) verify

.PHONY: test-all
test-all:
	$(MAKE) test-crud