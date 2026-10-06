{
  description = "Logos module for RLN membership gifter: client requests + gifter serve over libp2p";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder/0.3.1";
  };

  outputs = inputs@{ logos-module-builder, ... }:
    logos-module-builder.lib.mkLogosModule {
      src = ./.;
      configFile = ./metadata.json;
      flakeInputs = inputs;
    };
}
