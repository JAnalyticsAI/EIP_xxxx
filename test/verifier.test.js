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
});
