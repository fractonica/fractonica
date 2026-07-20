import { Stack } from "expo-router";
import { StatusBar } from "expo-status-bar";

import { colors } from "../src/ui/theme";

export default function RootLayout() {
  return (
    <>
      <StatusBar style="light" />
      <Stack
        screenOptions={{
          animation: "fade",
          contentStyle: { backgroundColor: colors.background },
          headerShown: false,
        }}
      />
    </>
  );
}

