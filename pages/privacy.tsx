import { useRouter } from 'next/router';
import { PolicyDialog } from '@/components/vera/PolicyDialog';
import Landing from './index';

export default function PrivacyPage() {
    const router = useRouter();
    return (
        <>
            <Landing />
            <PolicyDialog
                policy="privacy"
                defaultOpen
                onClose={() => {
                    void router.replace('/');
                }}
            />
        </>
    );
}
