# KYAgent hackathon demo (DELIVERY_PLAN §5). Both targets need MONGODB_URI (MongoDB Atlas);
# neither ever falls back to the in-memory store.
#
#   make demo-reset        restore the exact judging scenario (idempotent)
#   make demo              serve the API + dashboard on Atlas over that scenario
#   make demo CHECK=1      headless scenario + search-index check, exits non-zero on mismatch
#   make demo-seed         upsert the demo documents only (no clear, no index wait)

NODE ?= node

.PHONY: demo demo-reset demo-seed test test-atlas

demo:
	$(NODE) scripts/demo.js $(if $(CHECK),--check,)

demo-reset:
	$(NODE) scripts/demo-reset.js

demo-seed:
	$(NODE) scripts/demo-seed.js

test:
	npm test

test-atlas:
	npm run test:atlas
