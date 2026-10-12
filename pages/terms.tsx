import { useRouter } from 'next/router';
import { PolicyDialog } from '@/components/vera/PolicyDialog';
import Landing from './index';

export default function TermsPage() {
    const router = useRouter();
    return (
        <>
            <Landing />
            <PolicyDialog
                policy="terms"
                defaultOpen
                onClose={() => {
                    void router.replace('/');
                }}
            />
        </>
    );
}
