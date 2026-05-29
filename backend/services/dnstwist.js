/**
 * DNS Impersonation Service (dnstwist-style mutations)
 */

function generateMutations(domain) {
  const parts = domain.split('.');
  const name = parts[0];
  const tld = parts.slice(1).join('.');
  const results = new Set();

  // 1. Bitsquatting
  const masks = [1, 2, 4, 8, 16, 32, 64, 128];
  for (let i = 0; i < name.length; i++) {
    const charCode = name.charCodeAt(i);
    for (const mask of masks) {
      const squatted = charCode ^ mask;
      const char = String.fromCharCode(squatted);
      if (/[a-z0-9-]/.test(char)) {
        results.add(name.substring(0, i) + char + name.substring(i + 1) + '.' + tld);
      }
    }
  }

  // 2. Homoglyphs (Simple set)
  const glyphs = { 'a': 'o', 'l': '1', 'o': '0', 'e': '3', 's': '5', 't': '7' };
  for (let i = 0; i < name.length; i++) {
    const char = name[i];
    if (glyphs[char]) {
      results.add(name.substring(0, i) + glyphs[char] + name.substring(i + 1) + '.' + tld);
    }
  }

  // 3. Omission
  for (let i = 0; i < name.length; i++) {
    results.add(name.substring(0, i) + name.substring(i + 1) + '.' + tld);
  }

  // 4. Repetition
  for (let i = 0; i < name.length; i++) {
    results.add(name.substring(0, i) + name[i] + name[i] + name.substring(i + 1) + '.' + tld);
  }

  // 5. Transposition
  for (let i = 0; i < name.length; i++) {
    if (name[i+1]) {
      results.add(name.substring(0, i) + name[i+1] + name[i] + name.substring(i + 2) + '.' + tld);
    }
  }

  // 6. Addition
  const qwerty = 'qwertyuiopasdfghjklzxcvbnm';
  for (let i = 0; i < name.length + 1; i++) {
    for (const char of qwerty) {
      results.add(name.substring(0, i) + char + name.substring(i) + '.' + tld);
    }
  }

  // Filter out the original domain and very short strings
  results.delete(domain);
  return [...results].filter(d => d.split('.')[0].length >= 3).slice(0, 50); // Limit to 50 for performance
}

module.exports = { generateMutations };
