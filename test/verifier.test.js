const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Verifier precompile wrapper tests", function () {
  it("deploys MockVerifier and VerifierWrapper and verifies proofs", async function () {
    const [deployer] = await ethers.getSigners();

    // Deploy MockVerifier
    const Mock = await ethers.getContractFactory("MockVerifier");
    const mock = await Mock.connect(deployer).deploy();
    await mock.deployed();

    // Deploy VerifierWrapper pointing to mock verifier
    const Wrapper = await ethers.getContractFactory("VerifierWrapper");
    const wrapper = await Wrapper.connect(deployer).deploy(mock.address);
    await wrapper.deployed();

    // Non-empty proof should succeed (MockVerifier policy)
    const proof = ethers.utils.hexlify(ethers.utils.toUtf8Bytes("proof"));
    const publicInputs = ethers.utils.hexlify(ethers.utils.toUtf8Bytes("inputs"));

    const ok = await wrapper.verifyAggregatedProof(proof, publicInputs);
    expect(ok).to.equal(true);

    // Empty proof should fail
    const empty = "0x";
    const ok2 = await wrapper.verifyAggregatedProof(empty, publicInputs);
    expect(ok2).to.equal(false);
  });

  it("deploys ReferenceGroth16Verifier and returns false for invalid proof via wrapper", async function () {
    const [deployer] = await ethers.getSigners();

    // Prepare zeroed VK inputs for ReferenceGroth16Verifier
    const vk_alpha = [0, 0];
    const vk_beta = [0, 0, 0, 0];
    const vk_gamma = [0, 0, 0, 0];
    const vk_delta = [0, 0, 0, 0];
    const vk_ic = []; // empty means only IC[0] exists and publicInputs length must be 0

    // Deploy ReferenceGroth16Verifier
    const Ref = await ethers.getContractFactory("ReferenceGroth16Verifier");
    const ref = await Ref.connect(deployer).deploy(vk_alpha, vk_beta, vk_gamma, vk_delta, vk_ic);
    await ref.deployed();

    // Deploy VerifierWrapper pointing to reference verifier
    const Wrapper = await ethers.getContractFactory("VerifierWrapper");
    const wrapper = await Wrapper.connect(deployer).deploy(ref.address);
    await wrapper.deployed();

    // Build an all-zero proof: a, b, c fields zeroed
    const a = [0, 0];
    const b = [[0, 0], [0, 0]];
    const c = [0, 0];

    const proof = ethers.utils.defaultAbiCoder.encode(["uint256[2]","uint256[2][2]","uint256[2]"], [a, b, c]);
    const publicInputs = ethers.utils.defaultAbiCoder.encode(["uint256[]"], [[]]);

    const ok = await wrapper.verifyAggregatedProof(proof, publicInputs);
    expect(ok).to.equal(false);
  });

  it("(optional) uses generated Groth16 proof and vk to verify via wrapper (skipped if missing)", async function () {
    const fs = require('fs');
    const path = require('path');
    const out = path.join(__dirname, '..', 'zksnark_examples', 'out');
    const proofPath = path.join(out, 'proof.json');
    const vkPath = path.join(out, 'verification_key.json');
    if (!fs.existsSync(proofPath) || !fs.existsSync(vkPath)) {
      console.log('Skipping generated-proof test; run zksnark_examples/scripts/generate_groth16.sh first');
      return;
    }

    const [deployer] = await ethers.getSigners();

    const proof = JSON.parse(fs.readFileSync(proofPath));
    const publicInputs = JSON.parse(fs.readFileSync(path.join(out, 'public.json')));

    // Build ABI-encoded proof and publicInputs for ReferenceGroth16Verifier
    const encodedProof = ethers.utils.defaultAbiCoder.encode([
      'uint256[2]', 'uint256[2][2]', 'uint256[2]'
    ], [proof.pi_a, proof.pi_b, proof.pi_c]);

    const encodedPublic = ethers.utils.defaultAbiCoder.encode(['uint256[]'], [publicInputs]);

    // Parse vk and construct constructor args (simple parsing)
    const vk = JSON.parse(fs.readFileSync(vkPath));

    // Flatten IC
    const ic = [];
    for (const p of vk.IC) {
      ic.push(p[0].toString());
      ic.push(p[1].toString());
    }

    // Deploy ReferenceGroth16Verifier with vk components
    const Ref = await ethers.getContractFactory('ReferenceGroth16Verifier');
    const ref = await Ref.connect(deployer).deploy(
      vk.vk_alpha_1, // [x,y]
      [vk.vk_beta_2[0][0], vk.vk_beta_2[0][1], vk.vk_beta_2[1][0], vk.vk_beta_2[1][1]],
      [vk.vk_gamma_2[0][0], vk.vk_gamma_2[0][1], vk.vk_gamma_2[1][0], vk.vk_gamma_2[1][1]],
      [vk.vk_delta_2[0][0], vk.vk_delta_2[0][1], vk.vk_delta_2[1][0], vk.vk_delta_2[1][1]],
      ic
    );
    await ref.deployed();

    const Wrapper = await ethers.getContractFactory('VerifierWrapper');
    const wrapper = await Wrapper.connect(deployer).deploy(ref.address);
    await wrapper.deployed();

    // Call wrapper verify; expect true for valid proof
    const ok = await wrapper.verifyAggregatedProof(encodedProof, encodedPublic);
    expect(ok).to.equal(true);
  });
});
