# Changelog

## [1.5.1](https://github.com/madflojo/testcerts/compare/v1.5.0...v1.5.1) (2026-09-27)


### Bug Fixes

* address PR review hardening notes 🔍 ([9b2761a](https://github.com/madflojo/testcerts/commit/9b2761ae3ef0bbaed27d890c6eae01e83aa296eb))
* **ci:** align documentation hunter PR guidance 🧭 ([9c11007](https://github.com/madflojo/testcerts/commit/9c110074f9976702b98f846ec1c55530eb15d1f1))
* **ci:** deliver documentation hunts through PRs ([238c0c0](https://github.com/madflojo/testcerts/commit/238c0c0f0c823ba54e87d7e7ea71d1ea15997306))
* **ci:** harden hunter capacity checks ([f2e2db5](https://github.com/madflojo/testcerts/commit/f2e2db5d28c19b54f4767327de7bc7ae895878e8))
* **ci:** keep documentation hunts on the PR trail 🗺️ ([4664d19](https://github.com/madflojo/testcerts/commit/4664d19020c536b16ada53f63e0ac930e9004bbb))
* **ci:** keep inactive hunter weeks green ([9142c2e](https://github.com/madflojo/testcerts/commit/9142c2e355dafcf41dbbfb41dfff378a0ed06428))
* **ci:** preserve hunter rotation continuity ([0c581e5](https://github.com/madflojo/testcerts/commit/0c581e597afab1f823019c24a7393120f3256d7f))
* **release:** align changelog configuration ([9a22325](https://github.com/madflojo/testcerts/commit/9a2232590417c6ce4d6fdd3c771d190a3d138f87))
* **testcerts:** guard Cert and CertPool against nil receiver - Bug Hunter ([1474860](https://github.com/madflojo/testcerts/commit/1474860e467be36e1e1dd1487b733fe713212d22))
* **testcerts:** guard Cert and CertPool against nil receiver - Bug Hunter ([9e38c30](https://github.com/madflojo/testcerts/commit/9e38c30a1423726375a1087b32a02947ca399302))
* **testcerts:** validate PEM data before writing ToTempFile - Bug Hunter ([7b48e51](https://github.com/madflojo/testcerts/commit/7b48e51143256a01568944c895f52a925ae88b7b))
* **testcerts:** validate PEM data before writing ToTempFile - Bug Hunter ([4aa338d](https://github.com/madflojo/testcerts/commit/4aa338de50e692c882f661d85e54e678ff551523))


### Documentation

* **testcerts:** avoid err race in package doc example ([ebbce51](https://github.com/madflojo/testcerts/commit/ebbce51bbd198c1a430e20b2a75427dacbd2035b))
* **testcerts:** correct package usage example ([76198cb](https://github.com/madflojo/testcerts/commit/76198cb8ae727215ef82d2af868f675206be96dd))
* **testcerts:** fix stale API example in package doc - Documentation Hunter ([d9511d0](https://github.com/madflojo/testcerts/commit/d9511d082e84131da0be2108e62e52bd8290f759))
* **testcerts:** fix stale API example in package doc - Documentation Hunter ([5bdf4ac](https://github.com/madflojo/testcerts/commit/5bdf4ac345dc8e0536e6b8642411b661819ddbf0))


### Code Refactoring

* **kpconfig:** consolidate IP address validation duplication - Maintainability Hunter ([8414e14](https://github.com/madflojo/testcerts/commit/8414e140f45b30d28ae6f3485cfd47f636cb76b3))
* **kpconfig:** consolidate IP address validation duplication - Maintainability Hunter ([98c82d1](https://github.com/madflojo/testcerts/commit/98c82d124b968d131ad4183a5e7cec9dce710f17))
* **testcerts:** consolidate ToTempFile duplication - Maintainability Hunter ([2854d05](https://github.com/madflojo/testcerts/commit/2854d057a168ccf5dfe8c35688e08e1ffa598e6d))
* **testcerts:** consolidate ToTempFile duplication - Maintainability Hunter ([5de51f7](https://github.com/madflojo/testcerts/commit/5de51f77e169290594f81a336310f2ed4e6766ba))
* **testcerts:** use direct validation errors ([6069035](https://github.com/madflojo/testcerts/commit/606903598ea6b3c566a48b447c01090f25928be6))


### Tests

* **kpconfig:** cover Expired NotAfter contract - Testing Hunter ([df043f5](https://github.com/madflojo/testcerts/commit/df043f5981d446bc96bf8c9806b8cd51593e4592))
* **kpconfig:** cover Expired NotAfter contract - Testing Hunter ([994ac3e](https://github.com/madflojo/testcerts/commit/994ac3e935e6cbd0ed7d83ff982c7c4093386f42))
* **testcerts:** cover ConfigureTLSConfig nil-config and mismatch paths - Testing Hunter ([81f8a99](https://github.com/madflojo/testcerts/commit/81f8a99738418c1d841e3e8a2fca95484ef01115))
* **testcerts:** cover ConfigureTLSConfig nil-config and mismatch paths - Testing Hunter ([db761e7](https://github.com/madflojo/testcerts/commit/db761e7ae815ffe45bf23d7c60ddb2c9e162dc5c))
* **testcerts:** cover KeyPair.ToFile nil-receiver guard - Testing Hunter ([102a1b3](https://github.com/madflojo/testcerts/commit/102a1b3bc3df0d5204bdc28184e33a7e2c8d11d4))
* **testcerts:** cover temp-file validation branches ([d72ded4](https://github.com/madflojo/testcerts/commit/d72ded4fc0a075dcb3a05355ae76f0bebf124770))


### Continuous Integration

* **code-hunters:** rotate two hunts per week ([05fb4d1](https://github.com/madflojo/testcerts/commit/05fb4d119a1480a185aaadd8d9ee7f66e12c0155))
* **code-hunters:** schedule four independent hunts ([2f60942](https://github.com/madflojo/testcerts/commit/2f60942af63e14736a0a6c8eacb6e2916a0843e7))
* **code-hunters:** schedule four independent hunts ([81fa1f3](https://github.com/madflojo/testcerts/commit/81fa1f3be6262716bb5dafb6b8141c4e061a12dc))
* **release:** automate Go module releases ([c784b17](https://github.com/madflojo/testcerts/commit/c784b17b96016ac4e2032325175a4bc23fa93589))
* **release:** automate Go module releases ([46596f9](https://github.com/madflojo/testcerts/commit/46596f9a6285659c38ed1e4132de1c462eb0132d))


### Miscellaneous Chores

* **docs:** fixing docs correctness ([23f5472](https://github.com/madflojo/testcerts/commit/23f5472889f1884c805bea0ada2d77b3cd8f56db))
