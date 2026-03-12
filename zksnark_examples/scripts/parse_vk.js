const fs = require('fs');
const path = require('path');

const vkPath = path.join(__dirname, '..', 'out', 'verification_key.json');
const outPath = path.join(__dirname, '..', 'out', 'constructor_args.json');

if (!fs.existsSync(vkPath)) {
  console.error('verification_key.json not found; run generate_groth16.sh first');
  process.exit(1);
}

const vk = JSON.parse(fs.readFileSync(vkPath, 'utf8'));

// vk_alpha_1: [x, y]
const vk_alpha = vk.vk_alpha_1.map(s => s.toString());

// vk_beta_2: [[x1, x0], [y1, y0]] in snarkjs format
const vk_beta = [
  vk.vk_beta_2[0][0].toString(),
  vk.vk_beta_2[0][1].toString(),
  vk.vk_beta_2[1][0].toString(),
  vk.vk_beta_2[1][1].toString()
];

const vk_gamma = [
  vk.vk_gamma_2[0][0].toString(),
  vk.vk_gamma_2[0][1].toString(),
  vk.vk_gamma_2[1][0].toString(),
  vk.vk_gamma_2[1][1].toString()
];

const vk_delta = [
  vk.vk_delta_2[0][0].toString(),
  vk.vk_delta_2[0][1].toString(),
  vk.vk_delta_2[1][0].toString(),
  vk.vk_delta_2[1][1].toString()
];

// IC: array of [x, y]
const ic = [];
for (const pt of vk.IC) {
  ic.push(pt[0].toString());
  ic.push(pt[1].toString());
}

const out = { vk_alpha, vk_beta, vk_gamma, vk_delta, vk_ic: ic };
fs.writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log('Wrote constructor_args.json ->', outPath);
