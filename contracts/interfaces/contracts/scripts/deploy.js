const hre = require("hardhat");

async function main() {
  const [admin, attester] = await hre.ethers.getSigners();
  console.log("Admin:", admin.address);
  console.log("Sample Attester:", attester.address);

  const PoS = await hre.ethers.getContractFactory("PoSBT");
  const base = process.env.BASE_URI || "https://example.com/posbt/";
  const pos = await PoS.deploy("ProofOfSoul", "PoSBT", base);
  await pos.waitForDeployment();
  console.log("PoSBT:", await pos.getAddress());

  // attester rolü verelim
  await (await pos.grantAttester(attester.address)).wait();
  console.log("Granted ATTESTER_ROLE to:", attester.address);

  // örnek: revoker rolü admin'de zaten var (constructor set)
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
