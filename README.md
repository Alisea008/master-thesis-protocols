# A Secure Cryptographic CTI Sharing Protocol for Resource-Constrained Enterprise in Cloud-Assisted Environment

This repository contains the official source code and cryptographic protocol implementations developed for the Master's Thesis by **Alisea Bovo** at the **University of Padua (UniPD)**.

## Overview

Cyber Threat Intelligence (CTI) sharing is essential for modern organizations to proactively defend against cyberattacks. However, resource-constrained enterprises often rely on cloud-assisted environments to store, process, and share CTI data, introducing significant privacy, confidentiality, and trust challenges.

This project implements and evaluates Outsourced Multi-Party Private Set Intersection (OMPSI) and cryptographic protocols designed to enable secure, privacy-preserving CTI sharing in cloud-assisted settings while accommodating the computational limitations of resource-constrained enterprises and guaranteeing security properties such as **plausible deniability**.

## Repository Structure

The repository is organized into three main directories:

* **`pipeline_official_ompsi_alg1/` — Main Protocol (Algorithm 1)**
  * Contains the primary cryptographic CTI sharing protocol proposed in the thesis, optimized for resource-constrained enterprises operating in a cloud-assisted architecture.

* **`pipeline_official_ompsi_alg2/` — Alternative Protocol (Algorithm 2)**
  * Contains the alternative cryptographic construction designed for comparative evaluation (analyzing trade-offs in computational overhead, communication cost, and security assumptions).

* **`bloom-goes-boom/` — Plausible Deniability Verification**
  * Contains scripts, simulations, and tests demonstrating the **plausible deniability** property of the proposed scheme (ensuring that a party can convincingly deny having shared or generated specific CTI records).

## Prerequisites & Installation

Before running the code, make sure you have the required environment and dependencies installed:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Alisea008/master-thesis-protocols.git
   cd master-thesis-protocols
   ```

2. **Set up the environment:**
   *(Adjust according to the specific dependencies required inside each directory)*
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## Usage

Navigate into each folder to run the respective protocol or verification test (check the scripts inside each folder for exact entry points and parameters):

### 1. Running the Main Protocol (Algorithm 1)
```bash
cd pipeline_official_ompsi_alg1
# Run the main script inside this directory
```

### 2. Running the Alternative Protocol (Algorithm 2)
```bash
cd ../pipeline_official_ompsi_alg2
# Run the alternative script inside this directory
```

### 3. Testing Plausible Deniability
```bash
cd ../bloom-goes-boom
# Run the plausible deniability verification tests
```

## AI Assistance Disclaimer

Artificial Intelligence tools were utilized during the development of this codebase to assist with boilerplate code generation, refactoring, and general debugging. All cryptographic logic, protocol designs, and experimental validations were reviewed and verified by the author.

## License

This project is released for academic and research purposes. Please refer to the `LICENSE` file (if applicable) or contact the author for further details.
