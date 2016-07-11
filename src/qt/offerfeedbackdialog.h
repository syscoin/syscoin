#ifndef OFFERFEEDBACKDIALOG_H
#define OFFERFEEDBACKDIALOG_H

#include <QDialog>
class WalletModel;
namespace Ui {
    class OfferFeedbackDialog;
}

/** Dialog for editing an address and associated information.
 */
class OfferFeedbackDialog : public QDialog
{
    Q_OBJECT

public:
    enum OfferType {
        Buyer,
        Seller,
		None
    };
    explicit OfferFeedbackDialog(WalletModel* model, const QString &escrow, QWidget *parent = 0);
public Q_SLOTS:
	void on_feedbackButton_clicked();
	void on_cancelButton_clicked();
private:
	QString offer;
	QString accept;
	bool isYourAlias(const QString &alias);
	bool lookup(const QString &buyer, const QString &seller, const QString &offertitle, const QString &currency, const QString &total, const QString &systotal);
	OfferFeedbackDialog::OfferType findYourOfferRoleFromAliases(const QString &buyer, const QString &seller);
	WalletModel* walletModel;
    Ui::OfferFeedbackDialog *ui;
	QString escrow;
};

#endif // OFFERFEEDBACKDIALOG_H
