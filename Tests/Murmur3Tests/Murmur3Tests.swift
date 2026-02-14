import Foundation
import Testing

@testable import Murmur3

@Test func performance() async throws {
    let url = Bundle.module.url(forResource: "alice29", withExtension: "txt")!
    let data = try Data(contentsOf: url)
    let bufSize = 1024
    let iterations = 10

    var totalTime: Double = 0

    for i in 1...iterations {
        var mmh = Murmur3Hash()
        var index = 0

        let start = ContinuousClock().now

        repeat {
            var lastIndex = index + bufSize
            if lastIndex > data.count {
                lastIndex = data.count
            }

            let data2 = data[index..<lastIndex]
            mmh.update(data2)

            index += data2.count
            if index >= data.count {
                break
            }
        } while true

        let hex = mmh.digestHex()

        let elapsed = ContinuousClock().now - start
        let seconds = Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) * 1e-18
        totalTime += seconds

        #expect(hex == "ef12617f3e2a5f9a44b3598f2e09cd50")
        print("Run \(i): \(hex) in \(seconds * 1000)ms")
    }

    let average = totalTime / Double(iterations)
    print("Average over \(iterations) runs: \(average * 1000)ms")
}

@Test func fileDigestHex() throws {
    let url = Bundle.module.url(forResource: "alice29", withExtension: "txt")!
    let hex = try Murmur3Hash.digestHex(fileAt: url)
    #expect(hex == "ef12617f3e2a5f9a44b3598f2e09cd50")
}
