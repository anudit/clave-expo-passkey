import { Button, StyleSheet, Text, View } from 'react-native';

import { Passkey } from 'clave-expo-passkey';
import { useState } from 'react';

export default function App() {
    const [result, setResult] = useState<string>('');
    const supported = Passkey.isSupported();

    async function createPasskey() {
        const passkey = await Passkey.create(
            {
                displayName: 'User-DisplayName',
                id: 'dXNlcg==',
                name: 'User-Name',
            },
            '0x737472696e676368616c6c656e6765',
            {
                rp: {
                    id: 'vault.omnid.io',
                    name: 'Clave',
                },
                attestation: 'direct',
                authenticatorSelection: {
                    authenticatorAttachment: 'platform',
                    requireResidentKey: true,
                    residentKey: 'required',
                    userVerification: 'required',
                },
            },
        );
        console.log(JSON.stringify(passkey));
        setResult(JSON.stringify(passkey));
    }

    async function signWithPasskey() {
        const res = JSON.parse(result);
        const signature = await Passkey.authenticate(
            [res['id']],
            '0x737472696e676368616c6c656e6765',
            {
                rpId: 'vault.omnid.io',
                timeout: 30000,
            },
        );
        console.log(signature);
        setResult(JSON.stringify(signature));
    }

    async function log() {
        console.log(result);
    }

    return (
        <View style={styles.container}>
            <Text>Passkey supported: {supported ? 'Yes' : 'No'}</Text>
            <Text>Result: {result}</Text>
            <Button onPress={createPasskey} title="Create Passkey" />
            <Button onPress={signWithPasskey} title="Sign with Passkey" />
            <Button onPress={log} title="log" />
        </View>
    );
}

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#fff',
        alignItems: 'center',
        justifyContent: 'center',
    },
});
