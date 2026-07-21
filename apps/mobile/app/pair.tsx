import { useLocalSearchParams, useRouter } from "expo-router";

import { RecordsScreen } from "../src/features/records/RecordsScreen";

const PAIRING_INVITATION = /^fractonica-pairing:v1:[A-Za-z0-9_-]+$/;

export default function PairingRoute() {
  const router = useRouter();
  const parameters = useLocalSearchParams<{ invitation?: string | string[] }>();
  const candidate = Array.isArray(parameters.invitation)
    ? parameters.invitation[0]
    : parameters.invitation;
  const invitation = candidate && PAIRING_INVITATION.test(candidate) ? candidate : undefined;

  return (
    <RecordsScreen
      onClosePairing={() => router.replace("/")}
      pairingInvitation={invitation}
    />
  );
}
