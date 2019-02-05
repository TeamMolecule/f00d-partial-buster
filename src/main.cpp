#include "aes.h"
#include "hex.h"
#include "workload.h"
#include "multishotsolver.h"

#include <iostream>

// multishot example data: 7b1d29a16cf8ccab84f0b8a598e42fa6 937c0effba23b4f6df1f2c3d 6cc7e8fa0cfa9f0d 22b4b8c6
// singleshot example data: c6a13b37878f5b826f4f8162a1c8d879 7ab647b00424f83547b0f45a 13233734ed5cf161 a1a9376f
// both generate key: 000102030405060708090A0B0C0D0E0F
int main(int argc, char *argv[])
{
    Partials partials;

    if (argc != 7)
    {
        std::cout << "usage: f00d-partial-buster [--encrypt-partial/--decrypt-partial] [--encrypt-key/--decrypt-key] [full] [four] [eight] [twelve]" << std::endl;
        return 1;
    }

    std::string solverType1(argv[1]);
    std::string solverType2(argv[2]);
    partials.full = hex::decode(argv[3]);
    partials.four = hex::decode(argv[4]);
    partials.eight = hex::decode(argv[5]);
    partials.twelve = hex::decode(argv[6]);

    MultishotSolver::Type partialType = MultishotSolver::Encrypt;
    MultishotSolver::Type keyType = MultishotSolver::Encrypt;

    if (solverType1 == "--encrypt-partial" || solverType2 == "--encrypt-partial")
    {
        partialType = MultishotSolver::Encrypt;
    }

    else if (solverType1 == "--decrypt-partial" || solverType2 == "--decrypt-partial")
    {
        partialType = MultishotSolver::Decrypt;
    }

    else
    {
        std::cout << "missing solver partial parameters. use \"--encrypt-partial\" or \"--decrypt-partial\"" << std::endl;
        return 1;
    }

    if (solverType1 == "--encrypt-key" || solverType2 == "--encrypt-key")
    {
        keyType = MultishotSolver::Encrypt;
    }

    else if (solverType1 == "--decrypt-key" || solverType2 == "--decrypt-key")
    {
        keyType = MultishotSolver::Decrypt;
    }

    else
    {
        std::cout << "missing solver key parameters. use \"--encrypt-key\" or \"--decrypt-key\"" << std::endl;
        return 1;
    }

    MultishotSolver solver(partials, keyType, partialType);

    std::chrono::time_point<std::chrono::system_clock> start, end;
    start = std::chrono::system_clock::now();

    auto solution = solver.solve();
    auto key = solution.get();

    end = std::chrono::system_clock::now();
    std::chrono::duration<double> elapsed_seconds = end-start;

    if (!key)
    {
        std::cout << "failed: could not find a key" << std::endl;
    }
    else
    {
        std::cout << "calculated key: " << hex::encode(std::vector<uint8_t>(key->data.bytes, key->data.bytes+0x10)) << std::endl;
    }

    std::cout << "elapsed time: " << elapsed_seconds.count() << std::endl;
}
