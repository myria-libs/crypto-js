# npm-template-typescript

 Let developers who publish libraries via npm share with the team quickly 👍. Less time to set up utility tools to follow best practices in programming, and more time on the core features of the package 💪. Deliver our product to market faster 🚀

## This package template supports us

- [x] 1. **Customize configuration**: eslint, prettier, jest, typescript
- [x] 2. **Git hook**: ensure your code is qualified with lint when committing and test when pushing from your early stage on your local machine
- [x] 3. **CI jobs**: trigger on `each PR` or `Push event` to ensure jobs `Lint -> Build -> Test` are verified
- [x] 4. **CD (publish) jobs**: trigger when a `new tag` is pushed
    1. Create a new release with release notes based on your commit messages
    2. Publish the npm package to npmjs like [@myria/airdrop-js](https://www.npmjs.com/package/@myria/airdrop-js)
    3. Create | Update the Github page. DO not available for Github Free account on private repo
- [x] 4. Generate API documentation for Typescript.

## Prerequisites

The following tools need to be installed:

1. [Git](http://git-scm.com/)
2. [Node.js 18+](http://nodejs.org/)

## How to use

### Clone and rename with your

```bash
git clone git@github.com:myria-libs/npm-template-typescript.git
# rename to desire name folder
mv npm-template-typescript $desire_name
cd $desire_name
```

### Update necessary fields e.g. name, author, version, repository, etc in package.json file

we can manage our package.json via [npm-pkg](https://docs.npmjs.com/cli/v10/commands/npm-pkg)

```bash
npm pkg set <key>=<value> [<key>=<value> ...]
npm pkg get [<key> [<key> ...]]
npm pkg delete <key> [<key> ...]
npm pkg set [<array>[<index>].<key>=<value> ...]
npm pkg set [<array>[].<key>=<value> ...]
npm pkg fix
```

### Install dependencies and build it

```bash
# reinitialize existing Git repository
git init
# install dependencies
npm install | yarn install
# run build
npm run build | yarn build
```

### Implement your production code, write unit tests

### Verify or fix lint

```bash
# check lint's rules
npm run lint | yarn lint
# check lint's rules and try to fix
npm run lint:fix | yarn lint:fix
# format your code
npm run prettier:format | yarn prettier:format
```

### Verify unit test

```bash
npm test | yarn test
```

*Note: For developement build we can temporarily disable coverage requirement

1. go to ./configs/jest.config.ts
2. update coverageThreshold config to 0 

## Capabilities and Frameworks

| Capability           | Module                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dependence Framework | [typescript](https://www.npmjs.com/package/typescript) adds optional types to JavaScript that support tools for large-scale JavaScript applications                                                                                                                                     |
| Coding Standard      | [eslint](https://eslint.org/) statically analyzes your code to quickly find and fix problems based on opt-in [rules](https://eslint.org/docs/latest/rules/), [prettier](https://prettier.io/docs/en/) an opinionated code formatter to build and enforce a style guide on save, [eslint-config-prettier](https://github.com/prettier/eslint-config-prettier) to turns off all rules that are unnecessary or might conflict with Prettier. |
| Testing Framework    | [Jest](https://jestjs.io/) a delightful JavaScript Testing Framework with a focus on simplicity.                                                                                                                                                                                                                                                                                                                                          |
| Documentation Generator      | [TypeDoc](https://typedoc.org/guides/overview/) is a documentation generator for TypeScript, [http-server](https://www.npmjs.com/package/http-server) is a simple, zero-configuration command-line static HTTP server                                   |
| Useful Links         | [npmtrends](https://npmtrends.com/) Compare package download counts over time, [act](https://nektosact.com/introduction.html) run your GitHub Actions locally, [Actionlint](https://marketplace.visualstudio.com/items?itemName=arahata.linter-actionlint) static checker for GitHub Actions workflow files                                  |

## Collaboration

1. We use the git rebase strategy to keep tracking meaningful commit message. Help to enable rebase when pull `$ git config --local pull.rebase true`
2. Follow TypeScript Style Guide [Google](https://google.github.io/styleguide/tsguide.html)
3. Follow Best-Practices in coding:
    1. [Clean code](https://github.com/labs42io/clean-code-typescript) make team happy
    2. [Return early](https://szymonkrajewski.pl/why-should-you-return-early/) make code safer and use resource Efficiency
    3. [Truthy & Falsy](https://frontend.turing.edu/lessons/module-1/js-truthy-falsy-expressions.html) make code shorter
    4. [SOLID Principles](https://javascript.plainenglish.io/solid-principles-with-type-script-d0f9a0589ec5) make clean code
    5. [DRY & KISS](https://dzone.com/articles/software-design-principles-dry-and-kiss) avoid redundancy and make your code as simple as possible
4. Make buildable commit and pull latest code from `main` branch frequently
5. Follow the [Semantic Versioning](https://semver.org/) once we are ready for release
6. Use readable commit message [karma](http://karma-runner.github.io/6.3/dev/git-commit-msg.html) to let us use it in the release notes

```bash
     /‾‾‾‾‾‾‾‾
🔔  <  Ring! Please use semantic commit messages
     \________


<type>(<scope>): ([issue number]) <subject>
    │      │        |             │
    |      |        |             └─> subject in present tense. Not capitalized. No period at the end.
    |      |        |
    │      │        └─> Issue number (optional): Jira Ticket or Issue number
    │      │
    │      └─> Scope (optional): eg. Articles, Profile, Core
    │
    └─> Type: chore, docs, feat, fix, refactor, style, ci, perf, build, or test.
```
