module.exports = {
	semi: false,
	singleQuote: true,
	printWidth: 120,
	tabWidth: 4,
	trailingComma: 'es5',
	useTabs: true,
	bracketSpacing: true,
	arrowParens: 'avoid',
	overrides: [
		{
			files: '*.sol',
			options: {
				explicitTypes: 'always',
				compiler: '0.8.12',
			},
		},
	],
}
