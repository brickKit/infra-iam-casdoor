seed:  ## the seed data's test accounts in Casdoor (CASDOOR_URL, CASDOOR_ADMIN_PASSWORD, IAM_TEST_PASSWORD; see scripts/dev_setup.py)
	python3 -I scripts/dev_setup.py --users-only
.PHONY: seed
