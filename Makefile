.PHONY: validate test package

validate:
	python3 -m compileall -q app bin tools privileged tests
	bash -n deploy/*.sh scripts/*.sh


test: validate
	python3 tests/smoke_v331.py
	python3 tests/smoke_v340.py

package: test
	./scripts/package_release.sh
