{
  description = "Logos module for RLN membership gifter: client requests + gifter serve over libp2p";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder/0.3.1";
    # Name matches metadata.json#dependencies: the builder resolves the input
    # of that name and generates the libp2p_module bindings from its LIDL;
    # logoscore loads it before this module.
    libp2p_module.url = "git+https://github.com/logos-co/logos-libp2p-module?ref=refs/tags/v1.1.1";
  };

  outputs = inputs@{ logos-module-builder, ... }:
    logos-module-builder.lib.mkLogosModule {
      src = ./.;
      configFile = ./metadata.json;
      flakeInputs = inputs;
    };
}
