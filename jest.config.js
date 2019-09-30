module.exports = {
	preset: 'ts-jest',
	testEnvironment: 'node',
	collectCoverage: true,
	coverageReporters: ['json-summary', 'text-summary', 'lcov'],
	collectCoverageFrom: ['src/**/*.{ts,tsx}', '!**/node_modules/**'],
	notify: true,
	notifyMode: 'failure-change',
};
