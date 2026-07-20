Pod::Spec.new do |spec|
  spec.name = 'FractonicaClient'
  spec.version = '0.1.0'
  spec.summary = 'Native boundary for the Fractonica mobile client'
  spec.description = 'Expo module shell for the versioned Fractonica Rust client facade.'
  spec.author = 'Fractonica'
  spec.homepage = 'https://github.com/fractonica/fractonica'
  spec.license = 'AGPL-3.0-or-later'
  spec.platforms = { :ios => '16.4' }
  spec.source = { :git => 'https://github.com/fractonica/fractonica.git' }
  spec.static_framework = true

  spec.dependency 'ExpoModulesCore'
  spec.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  spec.source_files = '*.swift', 'Generated/*.swift'
  spec.vendored_frameworks = 'Rust/FractonicaMobileCoreFFI.xcframework'
  spec.frameworks = 'Security', 'SystemConfiguration'
  spec.libraries = 'c++', 'resolv', 'z'
end
