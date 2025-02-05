// utils.js
export function generateName(prefix) {
  const randomString = Math.random().toString(36).substring(2, 8);
  return `${prefix}-${randomString}`;
}