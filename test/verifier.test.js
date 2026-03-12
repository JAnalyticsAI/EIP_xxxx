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
});
