module.exports = {
  extends: ["@commitlint/config-conventional"],
  rules: {
    // Allow commits that match specific patterns (like WIP commits)
    'subject-empty': [2, 'never'],
    'type-empty': [2, 'never'],
  },
  ignores: [
    (message) => message.includes('Initial plan'),
  ],
};
